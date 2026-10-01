# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Portable governance; adapters execute effects, Norinth evaluates and records."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from app.dependencies import ActorContext
from app.schemas.portable import AuthorizationInput, ControlPack, RevisionManifest, RuntimePolicy
from app.services.authorization import AuthorizationError, require_permission
from app.storage import portable as store
from app.storage.organizations import organization_is_active
from app.storage.raw_events import count_unfolded


def instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HTTPException(422, "Timestamp must be an ISO-8601 instant") from error
    if parsed.tzinfo is None:
        raise HTTPException(422, "Timestamp must include its timezone")
    return parsed.astimezone(UTC)


def now() -> datetime:
    return datetime.now(UTC)


def require_human(actor: ActorContext, permission: str, target: dict[str, Any]) -> None:
    try:
        require_permission(actor, permission, target)
    except AuthorizationError as error:
        raise HTTPException(403, str(error)) from error


def resolve_principal(token: str | None) -> dict[str, Any]:
    with store.connect() as connection:
        credential = connection.execute(
            "SELECT * FROM portable_credentials WHERE token_hash = ? AND purpose = 'integration'",
            (store.token_hash(token or ""),),
        ).fetchone()
        if credential is None:
            raise HTTPException(401, "Invalid integration credential")
        record = store.load(connection, credential["tenant_id"], credential["record_id"], "integration")
    if not record["audited_at"] or record["state"] != "active" or not organization_is_active(record["tenant_id"]):
        raise HTTPException(403, "Integration or organization is inactive")
    return record


def principal_scope(principal: dict[str, Any], scope: str, target: dict[str, Any] | None = None) -> None:
    if scope not in principal["body"]["scopes"]:
        raise HTTPException(403, "Integration lacks required scope")
    if target and any(target[field] != principal[field] for field in ("tenant_id", "project", "environment")):
        raise HTTPException(404, "Portable record not found")


def ensure_source(connection, tenant: str, source_id: str, target: dict[str, Any]) -> None:
    source = store.load(connection, tenant, source_id, "integration")
    principal_scope(source, "observations:write", target)
    if not source["audited_at"] or source["state"] != "active":
        raise HTTPException(409, "Evidence source is inactive")


def create_integration(connection, tenant: str, body: dict[str, Any], actor: str) -> tuple[dict[str, Any], str]:
    if len({c["name"] for c in body["capabilities"]}) != len(body["capabilities"]):
        raise HTTPException(422, "Capability names must be unique")
    record = store.insert(
        connection,
        tenant_id=tenant,
        kind="integration",
        project=body["project"],
        environment=body["environment"],
        integration_id="",
        external_id=str(uuid4()),
        state="active",
        body=body,
        created_by=actor,
    )
    token = "nri_" + secrets.token_urlsafe(32)
    connection.execute(
        "INSERT INTO portable_credentials(token_hash,record_id,tenant_id,purpose) VALUES (?,?,?,'integration')",
        (store.token_hash(token), record["record_id"], tenant),
    )
    return record, token


def submit_system(connection, principal: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    principal_scope(principal, "systems:write")
    external_key = store.digest({"resource_type": body["resource_type"], "external_id": body["external_id"]})
    row = connection.execute(
        """SELECT * FROM portable_records WHERE tenant_id = ? AND kind = 'system'
        AND integration_id = ? AND external_id = ? AND project = ? AND environment = ?""",
        (principal["tenant_id"], principal["record_id"], external_key, principal["project"], principal["environment"]),
    ).fetchone()
    if row:
        record = store.decode(row)
        # Renames are harmless; changing purpose or a legacy evidence binding
        # invalidates the previous approval instead of inheriting it silently.
        changed = any(record["body"].get(k) != body.get(k) for k in ("purpose", "legacy_application_name"))
        state = "planned" if changed and record["state"] != "retired" else record["state"]
        connection.execute(
            "UPDATE portable_records SET body = ?, state = ?, updated_at = ?, audited_at = '' WHERE record_id = ?",
            (store.canonical(body), state, now().isoformat(), record["record_id"]),
        )
        return store.load(connection, principal["tenant_id"], record["record_id"])
    return store.insert(
        connection,
        tenant_id=principal["tenant_id"],
        kind="system",
        project=principal["project"],
        environment=principal["environment"],
        integration_id=principal["record_id"],
        external_id=external_key,
        state="planned",
        body=body,
        created_by="integration:" + principal["record_id"],
    )


def system_for_source(connection, principal: dict[str, Any], system_id: str, *, owner: bool = False) -> dict[str, Any]:
    system = store.load(connection, principal["tenant_id"], system_id, "system")
    principal_scope(principal, "systems:read", system)
    if owner and system["integration_id"] != principal["record_id"]:
        raise HTTPException(403, "Only the bound executor can submit revisions and execution receipts")
    return system


def submit_revision(
    connection,
    principal: dict[str, Any],
    system: dict[str, Any],
    manifest: dict[str, Any],
    *,
    actor_ref: str | None = None,
) -> dict[str, Any]:
    principal_scope(principal, "revisions:write", system)
    if system["state"] == "retired":
        raise HTTPException(409, "System is retired")
    key = store.digest({"system_id": system["record_id"], "revision": manifest["revision"]})
    row = connection.execute(
        "SELECT * FROM portable_records WHERE tenant_id = ? AND kind = 'revision' AND integration_id = ? AND external_id = ?",
        (principal["tenant_id"], principal["record_id"], key),
    ).fetchone()
    body = {"system_id": system["record_id"], "manifest": manifest, "manifest_digest": store.digest(manifest)}
    if row:
        record = store.decode(row)
        if record["body"] != body:
            raise HTTPException(409, "Revision names are immutable; submit a new revision")
        return record
    return store.insert(
        connection,
        tenant_id=principal["tenant_id"],
        kind="revision",
        project=system["project"],
        environment=system["environment"],
        integration_id=principal["record_id"],
        external_id=key,
        state="pending_review",
        body=body,
        created_by=actor_ref or "integration:" + principal["record_id"],
    )


def submit_observation(
    connection, principal: dict[str, Any], system: dict[str, Any], body: dict[str, Any]
) -> dict[str, Any]:
    principal_scope(principal, "observations:write", system)
    observed = instant(body["observed_at"])
    if observed > now():
        raise HTTPException(422, "Future observations cannot establish evidence")
    key = store.digest({"system_id": system["record_id"], "external_id": body["external_id"]})
    rows = connection.execute(
        "SELECT * FROM portable_records WHERE tenant_id = ? AND kind = 'observation' AND integration_id = ? AND external_id = ?",
        (principal["tenant_id"], principal["record_id"], key),
    ).fetchone()
    payload = {**body, "system_id": system["record_id"]}
    if rows:
        record = store.decode(rows)
        if record["body"] != payload:
            raise HTTPException(409, "Observations are immutable; use a new external id")
        return record
    return store.insert(
        connection,
        tenant_id=principal["tenant_id"],
        kind="observation",
        project=system["project"],
        environment=system["environment"],
        integration_id=principal["record_id"],
        external_id=key,
        state="recorded",
        body=payload,
        created_by="integration:" + principal["record_id"],
    )


def evidence(
    connection, system: dict[str, Any], revision_digest: str, checks: list[str], sources: list[str], age: int
) -> tuple[list[str], list[str]]:
    blockers, refs = [], []
    placeholders = ",".join("?" for _ in sources)
    for check in checks:
        # Indexed, revision-bound lookup: old receipts and unrelated revisions
        # cannot exhaust a scan window or hide a newer failed observation.
        row = connection.execute(
            f"""SELECT observation.* FROM portable_records observation
            JOIN portable_records source ON source.record_id = observation.integration_id
                AND source.tenant_id = observation.tenant_id AND source.kind = 'integration' AND source.state = 'active'
            WHERE observation.tenant_id = ? AND observation.kind = 'observation' AND observation.subject_id = ?
                AND observation.revision_digest = ? AND observation.check_id = ?
                AND observation.integration_id IN ({placeholders})
            ORDER BY observation.observed_at DESC, CASE observation.evidence_result WHEN 'failed' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
                observation.created_at DESC, observation.record_id LIMIT 1""",
            (system["tenant_id"], system["record_id"], revision_digest, check, *sources),
        ).fetchone()
        latest = store.decode(row) if row else None
        if latest is None:
            blockers.append("missing_evidence:" + check)
        elif not latest["audited_at"]:
            blockers.append("pending_evidence_audit:" + check)
        elif (now() - instant(latest["body"]["observed_at"])).total_seconds() > age:
            blockers.append("stale_evidence:" + check)
        elif latest["body"]["result"] == "unknown":
            blockers.append("unknown_evidence:" + check)
        elif latest["body"]["result"] != "passing":
            blockers.append("nonpassing_evidence:" + check)
        else:
            refs.append(latest["record_id"])
    return blockers, refs


def active_policy(connection, system: dict[str, Any]) -> dict[str, Any] | None:
    policies = store.records(
        connection, system["tenant_id"], "policy", subject_id=system["record_id"], state="active", limit=1
    )
    return next((p for p in policies if p["state"] == "active"), None)


def evaluate(connection, principal: dict[str, Any], request: AuthorizationInput) -> dict[str, Any]:
    revision = store.load(connection, principal["tenant_id"], request.revision_id, "revision")
    system = system_for_source(connection, principal, revision["body"]["system_id"], owner=True)
    policy = active_policy(connection, system)
    base = {
        "outcome": "indeterminate",
        "reasons": [],
        "system_id": system["record_id"],
        "revision_id": revision["record_id"],
        "manifest_digest": revision["body"]["manifest_digest"],
        "policy_id": policy["record_id"] if policy else None,
        "policy_digest": store.digest(policy["body"]["policy"]) if policy else None,
        "checked_at": now().isoformat(),
        "evidence_ids": [],
        "enforcement": "executor_required",
    }
    if principal["state"] != "active":
        return {**base, "outcome": "deny", "reasons": ["executor_inactive"]}
    if not principal["audited_at"]:
        return {**base, "reasons": ["executor_audit_pending"]}
    if system["state"] != "approved":
        return {
            **base,
            "outcome": "deny" if system["state"] == "retired" else "requires_review",
            "reasons": ["system_" + system["state"]],
        }
    if not system["audited_at"] or not revision["audited_at"] or (policy and not policy["audited_at"]):
        return {**base, "reasons": ["governance_audit_pending"]}
    if not policy:
        return {**base, "reasons": ["no_active_runtime_policy"]}
    rules = RuntimePolicy.model_validate(policy["body"]["policy"])
    manifest = RevisionManifest.model_validate(revision["body"]["manifest"])
    blockers = []
    for field in ("models", "tools", "resources"):
        if set(getattr(manifest, field)) - set(getattr(rules, field)):
            blockers.append("outside_policy:" + field)
    if manifest.autonomy_level > rules.max_autonomy:
        blockers.append("autonomy_exceeds_policy")
    if manifest.external_action and not rules.allow_external_action:
        blockers.append("external_action_not_allowed")
    if (
        rules.require_human_checkpoint
        or (manifest.untrusted_input and manifest.sensitive_data and manifest.external_action)
    ) and not manifest.human_checkpoint:
        blockers.append("human_checkpoint_required")
    if blockers and request.purpose != "remediation":
        return {**base, "outcome": "deny", "reasons": blockers}
    blockers = []
    if request.purpose in {"runtime", "remediation"} and request.action is None:
        raise HTTPException(422, "Runtime and remediation requests require an exact action")
    if request.purpose == "release" and request.action is not None:
        raise HTTPException(422, "Release requests cannot authorize an action")
    if request.action:
        action = request.action
        capabilities = {c["name"]: c for c in principal["body"]["capabilities"]}
        capability = capabilities.get(action.capability)
        permitted_actions = rules.remediation_actions if request.purpose == "remediation" else rules.actions
        if action.capability not in permitted_actions or capability is None:
            blockers.append("action_not_allowed")
        if action.resource_id not in rules.resources or action.resource_id not in manifest.resources:
            blockers.append("resource_not_allowed")
        if request.purpose == "remediation" and action.parameters != rules.action_parameters.get(action.capability, {}):
            blockers.append("remediation_parameters_not_preapproved")
        if capability:
            types = capability["parameter_types"]
            if set(action.parameters) != set(types):
                blockers.append("invalid_action_parameters")
            for k, value in action.parameters.items():
                expected = types.get(k)
                valid = (
                    (expected == "string" and isinstance(value, str) and len(value) <= 2000)
                    or (expected == "boolean" and isinstance(value, bool))
                    or (expected == "number" and isinstance(value, (int, float)) and not isinstance(value, bool))
                )
                if not valid:
                    blockers.append("invalid_action_parameter:" + k)
        if blockers:
            return {**base, "outcome": "deny", "reasons": blockers}
    if request.purpose == "remediation":
        return {**base, "outcome": "allow"}
    if system["body"].get("legacy_application_name") and count_unfolded(system["tenant_id"]):
        return {**base, "reasons": ["pending_legacy_evidence"]}
    legacy = system["body"].get("legacy_application_name")
    if legacy:
        for table, condition in (
            ("risk_findings", "status IN ('open', 'mitigation_required')"),
            ("control_assessments", "status = 'missing'"),
            ("change_events", "status = 'open'"),
        ):
            row = connection.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE tenant_id = ? AND project = ? AND environment = ? AND application_name = ? AND {condition}",
                (system["tenant_id"], system["project"], system["environment"], legacy),
            ).fetchone()
            if row["n"]:
                blockers.append("legacy_blocker:" + table)
    gaps, refs = evidence(
        connection,
        system,
        revision["body"]["manifest_digest"],
        rules.required_checks,
        rules.trusted_sources,
        rules.evidence_max_age_seconds,
    )
    if gaps or blockers:
        return {
            **base,
            "reasons": gaps + blockers,
            "outcome": "deny" if blockers or any(g.startswith("nonpassing") for g in gaps) else "indeterminate",
        }
    if revision["state"] != "approved":
        released = store.records(
            connection,
            system["tenant_id"],
            "receipt",
            subject_id=system["record_id"],
            revision_id=revision["record_id"],
            policy_id=policy["record_id"],
            purpose="release",
            limit=1,
        )
        routine = rules.allow_routine_releases and (
            request.purpose == "release"
            or (released and released[0]["audited_at"] and released[0]["body"]["outcome"] == "executed")
        )
        if not routine:
            return {**base, "outcome": "requires_review", "reasons": ["revision_requires_review"], "evidence_ids": refs}
    return {**base, "outcome": "allow", "evidence_ids": refs}


def issue_authorization(
    connection, principal: dict[str, Any], request: AuthorizationInput
) -> tuple[dict[str, Any], str | None]:
    principal_scope(principal, "authorizations:request")
    result = evaluate(connection, principal, request)
    record = store.insert(
        connection,
        tenant_id=principal["tenant_id"],
        kind="authorization",
        project=principal["project"],
        environment=principal["environment"],
        integration_id=principal["record_id"],
        external_id=str(uuid4()),
        state=result["outcome"],
        body={**result, "request": request.model_dump(), "request_digest": store.digest(request.model_dump())},
        created_by="integration:" + principal["record_id"],
    )
    if result["outcome"] != "allow":
        return record, None
    policy = store.load(connection, principal["tenant_id"], result["policy_id"], "policy")
    expires = (now() + timedelta(seconds=policy["body"]["policy"]["permit_ttl_seconds"])).isoformat()
    token = "nrp_" + secrets.token_urlsafe(32)
    connection.execute(
        "INSERT INTO portable_credentials(token_hash,record_id,tenant_id,purpose,expires_at) VALUES (?,?,?,'permit',?)",
        (store.token_hash(token), record["record_id"], principal["tenant_id"], expires),
    )
    return {**record, "expires_at": expires}, token


def consume_authorization(
    connection, principal: dict[str, Any], token: str, request: AuthorizationInput
) -> dict[str, Any]:
    principal_scope(principal, "authorizations:request")
    row = connection.execute(
        "SELECT * FROM portable_credentials WHERE token_hash = ? AND tenant_id = ? AND purpose = 'permit'",
        (store.token_hash(token), principal["tenant_id"]),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Permit not found")
    grant = store.load(connection, principal["tenant_id"], row["record_id"], "authorization")
    if grant["integration_id"] != principal["record_id"]:
        raise HTTPException(404, "Permit not found")
    if not grant["audited_at"]:
        raise HTTPException(409, "Authorization audit is pending")
    if row["consumed_at"] or instant(row["expires_at"]) <= now():
        raise HTTPException(409, "Permit consumed or expired")
    if store.digest(request.model_dump()) != grant["body"]["request_digest"]:
        raise HTTPException(409, "Permit does not match the proposed action")
    current = evaluate(connection, principal, request)
    if current["outcome"] != "allow" or current["policy_id"] != grant["body"]["policy_id"]:
        raise HTTPException(409, "Authorization is no longer eligible")
    connection.execute(
        "UPDATE portable_credentials SET consumed_at = ? WHERE token_hash = ?",
        (now().isoformat(), store.token_hash(token)),
    )
    return store.set_state(connection, grant, "consumed")


def decide(
    connection, actor: ActorContext, target: dict[str, Any], decision: str, rationale: str, expected_body_digest: str
) -> dict[str, Any]:
    kinds = {
        "approve_system": ("system", "review.decide", "approved"),
        "approve_revision": ("revision", "gate.decide", "approved"),
        "activate_policy": ("policy", "config.write", "active"),
        "activate_pack": ("pack", "config.write", "active"),
        "retire_system": ("system", "lifecycle.manage", "retired"),
    }
    kind, permission, state = kinds[decision]
    if target["kind"] != kind:
        raise HTTPException(422, "Decision does not match target type")
    require_human(actor, permission, target)
    if store.digest(target["body"]) != expected_body_digest:
        raise HTTPException(409, "Record changed after review; refresh it and make a new decision")
    if decision == "approve_system" and not target["body"].get("purpose", "").strip():
        raise HTTPException(409, "Declare the system purpose before approval")
    if target["created_by"] == actor.user_ref:
        raise HTTPException(403, "A different person must decide this work")
    if (kind in {"policy", "pack"} and target["state"] != "draft") or (
        kind in {"system", "revision"} and target["state"] in {"approved", "retired"}
    ):
        if not (decision == "retire_system" and target["state"] == "approved"):
            raise HTTPException(409, "Decision is terminal")
    if kind == "revision":
        principal = store.load(connection, target["tenant_id"], target["integration_id"], "integration")
        current = evaluate(
            connection, principal, AuthorizationInput(revision_id=target["record_id"], purpose="release")
        )
        if current["outcome"] not in {"allow", "requires_review"} or current["reasons"] not in [
            [],
            ["revision_requires_review"],
        ]:
            raise HTTPException(409, "Revision evidence or policy is not eligible")
    if kind in {"policy", "pack"}:
        for source_id in target["body"]["policy" if kind == "policy" else "pack"]["trusted_sources"]:
            ensure_source(connection, target["tenant_id"], source_id, target)
        for prior in store.records(
            connection,
            target["tenant_id"],
            kind,
            state="active",
            project=target["project"],
            environment=target["environment"],
            subject_id=target["body"].get("system_id", ""),
        ):
            if prior["state"] == "active" and (
                kind == "policy" or prior["body"]["pack"]["pack_id"] == target["body"]["pack"]["pack_id"]
            ):
                store.set_state(connection, prior, "superseded")
    decision_record = store.insert(
        connection,
        tenant_id=target["tenant_id"],
        kind="decision",
        project=target["project"],
        environment=target["environment"],
        integration_id="",
        external_id=str(uuid4()),
        state="recorded",
        body={
            "system_id": target["body"].get("system_id", target["record_id"]),
            "target_id": target["record_id"],
            "decision": decision,
            "rationale": rationale,
            "target_body_digest": store.digest(target["body"]),
            "target_snapshot": target["body"],
        },
        created_by=actor.user_ref,
    )
    return {
        **store.set_state(connection, target, state, decision_id=decision_record["record_id"]),
        "decision_record": decision_record,
    }


def record_receipt(connection, principal: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    principal_scope(principal, "receipts:write")
    grant = store.load(connection, principal["tenant_id"], body["authorization_id"], "authorization")
    if grant["integration_id"] != principal["record_id"] or grant["state"] != "consumed" or not grant["audited_at"]:
        raise HTTPException(409, "Receipt requires this executor's consumed authorization")
    existing = connection.execute(
        "SELECT * FROM portable_records WHERE tenant_id = ? AND kind = 'receipt' AND external_id = ?",
        (principal["tenant_id"], grant["record_id"]),
    ).fetchone()
    payload = {
        **body,
        "system_id": grant["body"]["system_id"],
        "verification_after": now().isoformat(),
        "revision_id": grant["body"]["revision_id"],
        "policy_id": grant["body"]["policy_id"],
        "purpose": grant["body"]["request"]["purpose"],
    }
    if existing:
        record = store.decode(existing)
        if any(record["body"][key] != body[key] for key in body):
            raise HTTPException(409, "Execution receipts are immutable")
        return record
    return store.insert(
        connection,
        tenant_id=principal["tenant_id"],
        kind="receipt",
        project=grant["project"],
        environment=grant["environment"],
        integration_id=principal["record_id"],
        external_id=grant["record_id"],
        state=("reported_executed" if payload["purpose"] == "release" else "verification_pending")
        if body["outcome"] == "executed"
        else "failed",
        body=payload,
        created_by="integration:" + principal["record_id"],
    )


def verify_receipt(connection, principal: dict[str, Any], receipt_id: str, observation_id: str) -> dict[str, Any]:
    principal_scope(principal, "observations:write")
    receipt = store.load(connection, principal["tenant_id"], receipt_id, "receipt")
    principal_scope(principal, "observations:write", receipt)
    if not receipt["audited_at"] or not observation_id:
        raise HTTPException(409, "Receipt audit is pending")
    if receipt["state"] != "verification_pending":
        raise HTTPException(409, "Receipt is not awaiting verification")
    observation = store.load(connection, principal["tenant_id"], observation_id, "observation")
    if not observation["audited_at"]:
        raise HTTPException(409, "Verification evidence audit is pending")
    if receipt["integration_id"] == principal["record_id"] or observation["integration_id"] != principal["record_id"]:
        raise HTTPException(403, "Verification requires an independent authenticated evidence source")
    grant = store.load(connection, principal["tenant_id"], receipt["body"]["authorization_id"], "authorization")
    policy = store.load(connection, principal["tenant_id"], grant["body"]["policy_id"], "policy")
    if principal["record_id"] not in policy["body"]["policy"]["trusted_sources"]:
        raise HTTPException(403, "Evidence source is not trusted by the authorizing policy")
    request = AuthorizationInput.model_validate(grant["body"]["request"])
    if request.action is None:
        raise HTTPException(409, "Release receipts do not establish remediation")
    executor = store.load(connection, principal["tenant_id"], receipt["integration_id"], "integration")
    capability = next(c for c in executor["body"]["capabilities"] if c["name"] == request.action.capability)
    expected = {
        "system_id": receipt["body"]["system_id"],
        "revision_digest": grant["body"]["manifest_digest"],
        "check_id": capability["verification_check"],
        "action_digest": grant["body"]["request_digest"],
        "resource_id": request.action.resource_id,
    }
    if any(observation["body"][k] != v for k, v in expected.items()):
        raise HTTPException(409, "Verification evidence does not match the correction")
    observed = instant(observation["body"]["observed_at"])
    if (
        observed < instant(receipt["body"]["verification_after"])
        or (now() - observed).total_seconds() > policy["body"]["policy"]["evidence_max_age_seconds"]
    ):
        raise HTTPException(409, "Verification must be fresh and observed after execution")
    store.insert(
        connection,
        tenant_id=receipt["tenant_id"],
        kind="verification",
        project=receipt["project"],
        environment=receipt["environment"],
        integration_id=principal["record_id"],
        external_id=receipt_id,
        state="recorded",
        body={"system_id": expected["system_id"], "receipt_id": receipt_id, "observation_id": observation_id},
        created_by="integration:" + principal["record_id"],
    )
    return store.set_state(connection, receipt, "verified" if observation["body"]["result"] == "passing" else "failed")


def assess_pack(
    connection, system: dict[str, Any], revision: dict[str, Any], pack_record: dict[str, Any]
) -> list[dict[str, Any]]:
    pack = ControlPack.model_validate(pack_record["body"]["pack"])
    result = []
    for control in pack.controls:
        applicable = system["body"]["resource_type"] in control.resource_types
        gaps, refs = evidence(
            connection,
            system,
            revision["body"]["manifest_digest"],
            control.check_ids,
            pack.trusted_sources,
            control.max_age_seconds,
        )
        if not pack_record["audited_at"] or not revision["audited_at"] or not system["audited_at"]:
            gaps = ["governance_audit_pending"]
        result.append(
            {
                "control_id": control.control_id,
                "name": control.name,
                "framework_refs": control.framework_refs,
                "status": "not_applicable"
                if not applicable
                else "passing"
                if not gaps
                else "failed"
                if any(g.startswith("nonpassing") for g in gaps)
                else "unknown",
                "reasons": gaps if applicable else [],
                "evidence_ids": refs if applicable else [],
                "pack_id": pack.pack_id,
                "pack_version": pack.version,
                "system_id": system["record_id"],
                "revision_id": revision["record_id"],
            }
        )
    return result

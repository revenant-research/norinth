# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Session-authorized setup/decisions and separately scoped machine contracts."""

from __future__ import annotations

import secrets
from contextlib import contextmanager
from datetime import timedelta
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Response

from app.dependencies import ActorContext, current_actor, mfa_enrollment_required, scoped_dependency
from app.schemas.events import ScopeFilter
from app.schemas.portable import (
    AuthorizationInput,
    ConsumeInput,
    ControlPack,
    DecisionInput,
    DelegationInput,
    IntegrationCreate,
    ObservationInput,
    ReceiptInput,
    RedeemInput,
    RevisionManifest,
    RuntimePolicy,
    SubmissionInput,
    SystemInput,
    VerificationInput,
)
from app.services import portable as engine
from app.services.authorization import actor_permissions
from app.storage import portable as store
from app.storage.audit import record_audit
from app.storage.workflow import load_platform_user

router = APIRouter()


def tenant(actor: ActorContext) -> str:
    if not actor.tenant_id or actor.is_super_admin:
        raise HTTPException(403, "An organization actor is required")
    return actor.tenant_id


def principal(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    scheme, _, token = (authorization or "").partition(" ")
    return engine.resolve_principal(token if scheme.lower() == "bearer" else None)


@contextmanager
def source_transaction(source: dict[str, Any]):
    with store.transaction(source["tenant_id"]) as connection:
        current = store.load(connection, source["tenant_id"], source["record_id"], "integration")
        if (
            not current["audited_at"]
            or current["state"] != "active"
            or not engine.organization_is_active(source["tenant_id"])
        ):
            raise HTTPException(403, "Integration is inactive")
        source.update(current)
        yield connection


def audit(actor: str, record: dict[str, Any], action: str) -> None:
    with store.connect() as connection:
        decision = (
            store.load(connection, record["tenant_id"], record["decision_id"], "decision")
            if record["decision_id"]
            else None
        )
    record_audit(
        actor_ref=actor,
        tenant_id=record["tenant_id"],
        action="portable." + action,
        target_type=record["kind"],
        target_id=record["record_id"],
        detail={"body_digest": store.digest(record["body"]), "state": record["state"], "decision_record": decision},
    )
    # The mutation exists before its hash-chained audit append. It cannot confer
    # permission until this exact state has been anchored; an audit failure
    # leaves it explicitly pending rather than granting unrecorded authority.
    timestamp = engine.now().isoformat()
    with store.connect() as connection:
        changed = connection.execute(
            """UPDATE portable_records SET audited_at = ?
            WHERE tenant_id = ? AND record_id = ? AND state = ? AND updated_at = ? AND body = ? AND decision_id = ?""",
            (
                timestamp,
                record["tenant_id"],
                record["record_id"],
                record["state"],
                record["updated_at"],
                store.canonical(record["body"]),
                record["decision_id"],
            ),
        )
        if changed.rowcount != 1:
            raise HTTPException(409, "Record changed before its audit completed; re-read current state")
    record["audited_at"] = timestamp


def source_audit(source: dict[str, Any], record: dict[str, Any], action: str) -> None:
    audit("integration:" + source["record_id"], record, action)


def human_target(
    connection, actor: ActorContext, record_id: str, permission: str | None = None, kind: str | None = None
) -> dict[str, Any]:
    record = store.load(connection, tenant(actor), record_id, kind)
    if permission:
        engine.require_human(actor, permission, record)
    return record


@router.get("/api/portable/integrations")
def integrations(
    scope: ScopeFilter = Depends(scoped_dependency),
    actor: ActorContext = Depends(current_actor),
    limit: int = 100,
    offset: int = 0,
):
    if not 1 <= limit <= 500 or not 0 <= offset <= 1000000:
        raise HTTPException(422, "Invalid pagination")
    if "config.write" not in actor_permissions(actor):
        raise HTTPException(403, "Integration management requires config.write")
    with store.connect() as connection:
        rows = store.records(
            connection,
            tenant(actor),
            "integration",
            project=scope.project,
            environment=scope.environment,
            limit=limit + 1,
            offset=offset,
        )
        visible = [row for row in rows[:limit] if "config.write" in actor_permissions(actor, row)]
        return {"integrations": visible, "has_more": len(rows) > limit, "offset": offset, "limit": limit}


@router.post("/api/portable/integrations")
def register_integration(payload: IntegrationCreate, response: Response, actor: ActorContext = Depends(current_actor)):
    response.headers["Cache-Control"] = "no-store"
    scope = {"tenant_id": tenant(actor), "project": payload.project, "environment": payload.environment}
    engine.require_human(actor, "config.write", scope)
    with store.transaction(tenant(actor)) as connection:
        record, token = engine.create_integration(connection, tenant(actor), payload.model_dump(), actor.user_ref)
    audit(actor.user_ref, record, "integration.create")
    return {"integration": record, "token": token}


@router.post("/api/portable/integrations/{integration_id}/revoke")
def revoke_integration(integration_id: str, actor: ActorContext = Depends(current_actor)):
    with store.transaction(tenant(actor)) as connection:
        record = human_target(connection, actor, integration_id, "config.write", "integration")
        record = store.set_state(connection, record, "revoked")
    audit(actor.user_ref, record, "integration.revoke")
    return {"integration": record}


@router.post("/api/portable/integrations/{integration_id}/rotate")
def rotate_integration(integration_id: str, response: Response, actor: ActorContext = Depends(current_actor)):
    response.headers["Cache-Control"] = "no-store"
    with store.transaction(tenant(actor)) as connection:
        record = human_target(connection, actor, integration_id, "config.write", "integration")
        if record["state"] != "active":
            raise HTTPException(409, "Revoked integrations cannot be revived by rotation")
        connection.execute(
            "DELETE FROM portable_credentials WHERE tenant_id = ? AND record_id = ? AND purpose = 'integration'",
            (tenant(actor), integration_id),
        )
        token = "nri_" + secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO portable_credentials(token_hash,record_id,tenant_id,purpose) VALUES (?,?,?,'integration')",
            (store.token_hash(token), integration_id, tenant(actor)),
        )
        record = store.set_state(connection, record, "active")
    audit(actor.user_ref, record, "integration.rotate")
    return {"integration": record, "token": token}


@router.get("/api/portable/systems")
def systems(scope: ScopeFilter = Depends(scoped_dependency), limit: int = 100, offset: int = 0):
    if not 1 <= limit <= 500 or not 0 <= offset <= 1000000:
        raise HTTPException(422, "Limit must be between 1 and 500")
    with store.connect() as connection:
        rows = store.records(
            connection,
            scope.tenant_id or "",
            "system",
            project=scope.project,
            environment=scope.environment,
            limit=limit + 1,
            offset=offset,
        )
    return {"systems": rows[:limit], "has_more": len(rows) > limit, "offset": offset, "limit": limit}


def workspace_snapshot(connection, system: dict[str, Any], offset: int) -> dict[str, Any]:
    if not 0 <= offset <= 1000000:
        raise HTTPException(422, "Invalid history offset")
    result: dict[str, Any] = {"system": system, "offset": offset}
    for kind in ("revision", "policy", "authorization", "receipt", "decision", "observation", "verification"):
        rows = store.records(
            connection, system["tenant_id"], kind, subject_id=system["record_id"], limit=101, offset=offset
        )
        result[kind + "s"] = rows[:100]
        result[kind + "s_has_more"] = len(rows) > 100
    pack_rows = store.records(
        connection,
        system["tenant_id"],
        "pack",
        project=system["project"],
        environment=system["environment"],
        limit=101,
        offset=offset,
    )
    result["packs"] = pack_rows[:100]
    result["packs_has_more"] = len(pack_rows) > 100
    result["active_policy"] = engine.active_policy(connection, system)
    source = store.load(connection, system["tenant_id"], system["integration_id"], "integration")
    result["integration"] = source
    result["eligibility"] = {
        r["record_id"]: engine.evaluate(
            connection, source, AuthorizationInput(revision_id=r["record_id"], purpose="release")
        )
        for r in result["revisions"]
    }
    return result


@router.get("/api/portable/systems/{system_id}")
def system_detail(system_id: str, offset: int = 0, actor: ActorContext = Depends(current_actor)):
    with store.connect() as connection:
        return workspace_snapshot(connection, human_target(connection, actor, system_id, kind="system"), offset)


@router.get("/v1/portable/systems/{system_id}/workspace")
def machine_workspace(system_id: str, offset: int = 0, source: dict[str, Any] = Depends(principal)):
    with store.connect() as connection:
        return workspace_snapshot(connection, engine.system_for_source(connection, source, system_id), offset)


@router.post("/v1/portable/systems")
def register_system(payload: SystemInput, source: dict[str, Any] = Depends(principal)):
    with source_transaction(source) as connection:
        record = engine.submit_system(connection, source, payload.model_dump())
    source_audit(source, record, "system.upsert")
    return {"system": record}


@router.get("/v1/portable/systems/{system_id}")
def read_system(system_id: str, source: dict[str, Any] = Depends(principal)):
    with store.connect() as connection:
        return {"system": engine.system_for_source(connection, source, system_id)}


@router.post("/v1/portable/systems/{system_id}/revisions")
def register_revision(system_id: str, payload: RevisionManifest, source: dict[str, Any] = Depends(principal)):
    with source_transaction(source) as connection:
        system = engine.system_for_source(connection, source, system_id, owner=True)
        record = engine.submit_revision(connection, source, system, payload.model_dump())
    source_audit(source, record, "revision.submit")
    return {"revision": record}


@router.post("/api/portable/submissions")
def human_submission(payload: SubmissionInput, actor: ActorContext = Depends(current_actor)):
    with store.transaction(tenant(actor)) as connection:
        system = human_target(connection, actor, payload.system_id, "intake.submit", "system")
        source = store.load(connection, tenant(actor), payload.integration_id, "integration")
        if source["state"] != "active":
            raise HTTPException(409, "Integration is inactive")
        engine.system_for_source(connection, source, payload.system_id, owner=True)
        record = engine.submit_revision(
            connection, source, system, payload.manifest.model_dump(), actor_ref=actor.user_ref
        )
    audit(actor.user_ref, record, "revision.submit")
    return {"revision": record}


@router.post("/v1/portable/systems/{system_id}/observations")
def register_observation(system_id: str, payload: ObservationInput, source: dict[str, Any] = Depends(principal)):
    with source_transaction(source) as connection:
        system = engine.system_for_source(connection, source, system_id)
        record = engine.submit_observation(connection, source, system, payload.model_dump())
    source_audit(source, record, "observation.submit")
    return {"observation": record}


@router.post("/api/portable/systems/{system_id}/policies")
def draft_policy(system_id: str, payload: RuntimePolicy, actor: ActorContext = Depends(current_actor)):
    with store.transaction(tenant(actor)) as connection:
        system = human_target(connection, actor, system_id, "config.write", "system")
        for source_id in payload.trusted_sources:
            engine.ensure_source(connection, tenant(actor), source_id, system)
        record = store.insert(
            connection,
            tenant_id=tenant(actor),
            kind="policy",
            project=system["project"],
            environment=system["environment"],
            integration_id="",
            external_id=str(uuid4()),
            state="draft",
            body={"system_id": system_id, "policy": payload.model_dump()},
            created_by=actor.user_ref,
        )
    audit(actor.user_ref, record, "policy.draft")
    return {"policy": record}


@router.post("/api/portable/records/{record_id}/{decision}")
def human_decision(record_id: str, decision: str, payload: DecisionInput, actor: ActorContext = Depends(current_actor)):
    if decision not in {"approve_system", "approve_revision", "activate_policy", "activate_pack", "retire_system"}:
        raise HTTPException(422, "Unsupported decision")
    with store.transaction(tenant(actor)) as connection:
        target = human_target(connection, actor, record_id)
        record = engine.decide(connection, actor, target, decision, payload.rationale)
    audit(actor.user_ref, record, decision)
    return {"record": record}


@router.post("/v1/portable/authorizations")
def authorize(payload: AuthorizationInput, response: Response, source: dict[str, Any] = Depends(principal)):
    response.headers["Cache-Control"] = "no-store"
    with source_transaction(source) as connection:
        record, token = engine.issue_authorization(connection, source, payload)
    source_audit(source, record, "authorization.evaluate")
    return {"authorization": record, "token": token}


@router.post("/v1/portable/authorizations/consume")
def consume(payload: ConsumeInput, response: Response, source: dict[str, Any] = Depends(principal)):
    response.headers["Cache-Control"] = "no-store"
    with source_transaction(source) as connection:
        record = engine.consume_authorization(connection, source, payload.token, payload.request)
    source_audit(source, record, "authorization.consume")
    return {"authorization": record}


@router.post("/v1/portable/receipts")
def receipt(payload: ReceiptInput, source: dict[str, Any] = Depends(principal)):
    with source_transaction(source) as connection:
        record = engine.record_receipt(connection, source, payload.model_dump())
    source_audit(source, record, "receipt.record")
    return {"receipt": record}


@router.post("/v1/portable/receipts/{receipt_id}/verify")
def verify(receipt_id: str, payload: VerificationInput, source: dict[str, Any] = Depends(principal)):
    with source_transaction(source) as connection:
        record = engine.verify_receipt(connection, source, receipt_id, payload.observation_id)
    source_audit(source, record, "receipt.verify")
    return {"receipt": record}


@router.post("/api/portable/control-packs")
def draft_pack(
    payload: ControlPack, scope: ScopeFilter = Depends(scoped_dependency), actor: ActorContext = Depends(current_actor)
):
    if not scope.project or not scope.environment:
        raise HTTPException(422, "Control packs require explicit project and environment")
    engine.require_human(actor, "config.write", scope.model_dump())
    if len({c.control_id for c in payload.controls}) != len(payload.controls):
        raise HTTPException(422, "Control ids must be unique")
    key = store.digest({"pack_id": payload.pack_id, "version": payload.version})
    with store.transaction(tenant(actor)) as connection:
        for source_id in payload.trusted_sources:
            engine.ensure_source(connection, tenant(actor), source_id, scope.model_dump())
        existing = connection.execute(
            "SELECT * FROM portable_records WHERE tenant_id = ? AND kind = 'pack' AND project = ? AND environment = ? AND external_id = ?",
            (tenant(actor), scope.project, scope.environment, key),
        ).fetchone()
        if existing:
            record = store.decode(existing)
            if record["body"]["pack"] != payload.model_dump():
                raise HTTPException(409, "Control pack versions are immutable")
        else:
            record = store.insert(
                connection,
                tenant_id=tenant(actor),
                kind="pack",
                project=scope.project,
                environment=scope.environment,
                integration_id="",
                external_id=key,
                state="draft",
                body={"pack": payload.model_dump()},
                created_by=actor.user_ref,
            )
    audit(actor.user_ref, record, "pack.draft")
    return {"pack": record}


def control_snapshot(connection, system: dict[str, Any], revision_id: str) -> dict[str, Any]:
    revision = store.load(connection, system["tenant_id"], revision_id, "revision")
    if revision["body"]["system_id"] != system["record_id"]:
        raise HTTPException(404, "Revision not found for system")
    packs = store.records(
        connection,
        system["tenant_id"],
        "pack",
        state="active",
        project=system["project"],
        environment=system["environment"],
        limit=501,
    )
    if len(packs) > 500:
        raise HTTPException(409, "Too many active packs to assess completely")
    return {
        "assessments": [
            assessment for pack in packs for assessment in engine.assess_pack(connection, system, revision, pack)
        ],
        "basis": "Mapped controls for this system and revision only; not certification or full framework coverage.",
    }


@router.get("/api/portable/systems/{system_id}/controls")
def portable_controls(system_id: str, revision_id: str, actor: ActorContext = Depends(current_actor)):
    with store.connect() as connection:
        return control_snapshot(connection, human_target(connection, actor, system_id, kind="system"), revision_id)


@router.get("/v1/portable/systems/{system_id}/controls")
def machine_controls(system_id: str, revision_id: str, source: dict[str, Any] = Depends(principal)):
    with store.connect() as connection:
        return control_snapshot(connection, engine.system_for_source(connection, source, system_id), revision_id)


@router.post("/api/portable/delegations")
def delegate(payload: DelegationInput, response: Response, actor: ActorContext = Depends(current_actor)):
    response.headers["Cache-Control"] = "no-store"
    # Validate the entire intended decision now; rollback the trial decision so
    # neither authority nor the rationale can be replaced by the integration.
    with store.transaction(tenant(actor)) as connection:
        source = store.load(connection, tenant(actor), payload.integration_id, "integration")
        target = human_target(connection, actor, payload.target_id)
        engine.principal_scope(source, "systems:read", target)
        if source["state"] != "active":
            raise HTTPException(409, "Integration is inactive")
        connection.execute("SAVEPOINT delegation_check")
        try:
            engine.decide(connection, actor, target, payload.decision, payload.rationale)
        finally:
            connection.execute("ROLLBACK TO SAVEPOINT delegation_check")
            connection.execute("RELEASE SAVEPOINT delegation_check")
        record = store.insert(
            connection,
            tenant_id=tenant(actor),
            kind="delegation",
            project=target["project"],
            environment=target["environment"],
            integration_id=source["record_id"],
            external_id=str(uuid4()),
            state="pending",
            body=payload.model_dump(),
            created_by=actor.user_ref,
        )
        token = "nrd_" + secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO portable_credentials(token_hash,record_id,tenant_id,purpose,expires_at) VALUES (?,?,?,'delegation',?)",
            (
                store.token_hash(token),
                record["record_id"],
                tenant(actor),
                (engine.now() + timedelta(seconds=60)).isoformat(),
            ),
        )
    audit(actor.user_ref, record, "delegation.create")
    return {"delegation": record, "token": token}


@router.post("/v1/portable/delegations/redeem")
def redeem(payload: RedeemInput, source: dict[str, Any] = Depends(principal)):
    with source_transaction(source) as connection:
        row = connection.execute(
            "SELECT * FROM portable_credentials WHERE token_hash = ? AND tenant_id = ? AND purpose = 'delegation'",
            (store.token_hash(payload.token), source["tenant_id"]),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Delegation not found")
        delegation = store.load(connection, source["tenant_id"], row["record_id"], "delegation")
        if delegation["integration_id"] != source["record_id"]:
            raise HTTPException(404, "Delegation not found")
        if not delegation["audited_at"]:
            raise HTTPException(409, "Delegation audit is pending")
        if row["consumed_at"] or engine.instant(row["expires_at"]) <= engine.now():
            raise HTTPException(409, "Delegation expired or consumed")
        user = load_platform_user(delegation["created_by"])
        if not user or user.get("tenant_id") != source["tenant_id"] or mfa_enrollment_required(user):
            raise HTTPException(403, "Delegated actor is unavailable or must enroll MFA")
        actor = ActorContext(user_ref=delegation["created_by"], tenant_id=source["tenant_id"])
        target = store.load(connection, source["tenant_id"], delegation["body"]["target_id"])
        engine.principal_scope(source, "systems:read", target)
        record = engine.decide(
            connection, actor, target, delegation["body"]["decision"], delegation["body"]["rationale"]
        )
        connection.execute(
            "UPDATE portable_credentials SET consumed_at = ? WHERE token_hash = ?",
            (engine.now().isoformat(), store.token_hash(payload.token)),
        )
        store.set_state(connection, delegation, "consumed")
    audit(actor.user_ref, record, delegation["body"]["decision"])
    return {"record": record}


@router.post("/api/portable/records/{record_id}/audit/retry")
def retry_audit(record_id: str, actor: ActorContext = Depends(current_actor)):
    permissions = {
        "system": "review.decide",
        "revision": "gate.decide",
        "policy": "config.write",
        "pack": "config.write",
        "integration": "config.write",
    }
    with store.connect() as connection:
        record = human_target(connection, actor, record_id)
        permission = permissions.get(record["kind"])
        if permission is None:
            raise HTTPException(422, "Record must be retried through its original machine contract")
        engine.require_human(actor, permission, record)
    audit(actor.user_ref, record, "audit.retry")
    return {"record": record}

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import json
from typing import Any

from . import db
from .attestation_keys import tenant_requires_attestation
from .entities import as_object, entity_id
from .errors import DomainError, RecordNotFound
from .raw_events import connect
from .scoping import count_scoped_rows, scoped_rows


def init_deployments() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_deployments (
                deployment_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT '',
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                current_version TEXT NOT NULL,
                current_status TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                artifact_ref TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (tenant_id, project, environment, deployment_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS deployment_versions (
                version_id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                artifact_ref TEXT NOT NULL,
                prompt_version TEXT,
                deployed_by TEXT,
                trace_id TEXT NOT NULL,
                observed_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS deployment_approval_gates (
                gate_id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                gate_status TEXT NOT NULL,
                required_reason TEXT NOT NULL,
                risk_count INTEGER NOT NULL,
                missing_control_count INTEGER NOT NULL,
                material_change_count INTEGER NOT NULL,
                prompt_version_id TEXT,
                prompt_evidence_status TEXT NOT NULL DEFAULT 'missing',
                passing_eval_count INTEGER NOT NULL DEFAULT 0,
                actor_ref TEXT,
                rationale TEXT,
                submitted_at TEXT NOT NULL,
                decided_at TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        for statement in (
            "ALTER TABLE deployment_approval_gates ADD COLUMN prompt_version_id TEXT",
            "ALTER TABLE deployment_approval_gates ADD COLUMN prompt_evidence_status TEXT NOT NULL DEFAULT 'missing'",
            "ALTER TABLE deployment_approval_gates ADD COLUMN passing_eval_count INTEGER NOT NULL DEFAULT 0",
        ):
            try:
                connection.execute(statement)
            except db.OperationalError:
                pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_governance_deployments_scope ON governance_deployments(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_deployment_versions_scope ON deployment_versions(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_deployment_approval_gates_scope ON deployment_approval_gates(tenant_id, project, environment)")


def process_deployment_events(events: list[dict[str, Any]]) -> None:
    with connect() as connection:
        for event in events:
            if event["type"] == "deployment.event":
                upsert_deployment_event(connection, event)


def upsert_deployment_event(connection, event: dict[str, Any]) -> None:
    attrs = event.get("attributes") or {}
    metadata = as_object(attrs.get("metadata"))
    deployment_id = attrs["deployment_id"]
    version = attrs["version"]
    application_name = metadata.get("application_name")
    workflow_name = metadata.get("workflow_name")
    if not application_name or not workflow_name:
        return
    status = attrs.get("deployment_status") or event.get("status", "observed")
    tenant = metadata.get("tenant_id") or ""
    version_id = entity_id("deployment-version", tenant, event["project"], event["environment"], deployment_id, version)
    connection.execute(
        """
        INSERT INTO governance_deployments (
            deployment_id, tenant_id, project, environment, application_name, workflow_name,
            current_version, current_status, provider, model, artifact_ref, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, project, environment, deployment_id) DO UPDATE SET
            current_version=excluded.current_version,
            current_status=excluded.current_status,
            provider=excluded.provider,
            model=excluded.model,
            artifact_ref=excluded.artifact_ref,
            last_seen=excluded.last_seen
        """,
        (
            deployment_id,
            metadata.get("tenant_id") or "",
            event["project"],
            event["environment"],
            application_name,
            workflow_name,
            version,
            status,
            attrs.get("provider"),
            attrs.get("model"),
            attrs["artifact_ref"],
            event["timestamp"],
            event["timestamp"],
        ),
    )
    connection.execute(
        """
        INSERT INTO deployment_versions (
            version_id, deployment_id, tenant_id, project, environment, application_name, workflow_name,
            version, status, provider, model, artifact_ref, prompt_version, deployed_by, trace_id, observed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(version_id) DO UPDATE SET
            status=excluded.status,
            provider=excluded.provider,
            model=excluded.model,
            artifact_ref=excluded.artifact_ref,
            prompt_version=excluded.prompt_version,
            deployed_by=excluded.deployed_by,
            trace_id=excluded.trace_id,
            observed_at=excluded.observed_at
        """,
        (
            version_id,
            deployment_id,
            tenant,
            event["project"],
            event["environment"],
            application_name,
            workflow_name,
            version,
            status,
            attrs.get("provider"),
            attrs.get("model"),
            attrs["artifact_ref"],
            attrs.get("prompt_version"),
            attrs.get("deployed_by"),
            event["trace_id"],
            event["timestamp"],
        ),
    )


def refresh_deployment_gates(scopes: list[dict[str, Any]] | None = None) -> None:
    """recompute gate evidence; scopes limits to the apps an ingest touched,
    None does every version"""
    wanted = None if scopes is None else {(s.get("tenant_id"), s["project"], s["environment"], s["application_name"]) for s in scopes}
    with connect() as connection:
        versions = connection.execute("SELECT * FROM deployment_versions ORDER BY observed_at DESC").fetchall()
        for version in versions:
            record = dict(version)
            if wanted is not None and (record.get("tenant_id"), record["project"], record["environment"], record["application_name"]) not in wanted:
                continue
            upsert_deployment_gate(connection, record)


def gate_required_reason(connection, evidence: dict[str, Any], tenant_id: str | None) -> str:
    """what is still blocking this gate, for the reviewer"""
    parts = []
    if evidence["risk_count"]:
        parts.append(f"{evidence['risk_count']} open risk findings")
    if evidence["missing_control_count"]:
        parts.append(f"{evidence['missing_control_count']} missing controls")
    if evidence["material_change_count"] > int(evidence.get("max_open_material_changes") or 0):
        parts.append(f"{evidence['material_change_count']} material changes")
    if evidence["prompt_evidence_status"] != "linked":
        parts.append("missing linked prompt version")
    if evidence["passing_eval_count"] == 0:
        require_attested = evidence.get("require_attested_evals")
        if require_attested is None:
            require_attested = tenant_requires_attestation(tenant_id, connection)
        parts.append(
            "missing attested passing eval evidence" if require_attested else "missing passing eval evidence"
        )
    return "; ".join(parts) if parts else "No blocking governance evidence detected"


def live_gate_evidence(connection, gate: dict[str, Any]) -> dict[str, Any]:
    """recompute a gate's blockers from current state

    the stored counts are only refreshed when telemetry arrives, so a reviewer
    who accepts the open risks or waives the missing controls does not change
    them. approval reads these live values instead, otherwise the remediation
    the gate asks for cannot actually clear it
    """
    row = connection.execute(
        "SELECT * FROM deployment_versions WHERE version_id = ?", (gate.get("version_id"),)
    ).fetchone()
    version = dict(row) if row is not None else {}
    return gate_evidence_counts(
        connection,
        {
            "tenant_id": gate.get("tenant_id"),
            "project": gate["project"],
            "environment": gate["environment"],
            "application_name": gate["application_name"],
            "workflow_name": gate["workflow_name"],
            "prompt_version": version.get("prompt_version"),
            "artifact_ref": version.get("artifact_ref"),
        },
    )


def upsert_deployment_gate(connection, version: dict[str, Any]) -> None:
    evidence = gate_evidence_counts(connection, version)
    gate_id = entity_id("deployment-gate", version["version_id"])
    existing = connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone()
    current_status = existing["gate_status"] if existing else None
    # never auto-approve: undecided gates stay pending_review until a human
    # approves or rejects via the guarded /approve|/reject endpoints; an existing
    # human decision is preserved. approvability (linked prompt + passing eval, no
    # open blockers) is enforced at approval time by set_deployment_gate_status;
    # the reasons below tell the reviewer what is still outstanding
    gate_status = current_status if current_status in {"approved", "rejected"} else "pending_review"
    required_reason = gate_required_reason(connection, evidence, version.get("tenant_id"))
    connection.execute(
        """
        INSERT INTO deployment_approval_gates (
            gate_id, deployment_id, version_id, tenant_id, project, environment, application_name, workflow_name,
            gate_status, required_reason, risk_count, missing_control_count, material_change_count,
            prompt_version_id, prompt_evidence_status, passing_eval_count, policy_tenant, policy_version,
            actor_ref, rationale, submitted_at, decided_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, datetime('now'), NULL, datetime('now'))
        ON CONFLICT(gate_id) DO UPDATE SET
            gate_status=excluded.gate_status,
            required_reason=excluded.required_reason,
            risk_count=excluded.risk_count,
            missing_control_count=excluded.missing_control_count,
            material_change_count=excluded.material_change_count,
            prompt_version_id=excluded.prompt_version_id,
            prompt_evidence_status=excluded.prompt_evidence_status,
            passing_eval_count=excluded.passing_eval_count,
            policy_tenant=excluded.policy_tenant,
            policy_version=excluded.policy_version,
            updated_at=datetime('now')
        """,
        (
            gate_id,
            version["deployment_id"],
            version["version_id"],
            version.get("tenant_id"),
            version["project"],
            version["environment"],
            version["application_name"],
            version["workflow_name"],
            gate_status,
            required_reason,
            evidence["risk_count"],
            evidence["missing_control_count"],
            evidence["material_change_count"],
            evidence["prompt_version_id"],
            evidence["prompt_evidence_status"],
            evidence["passing_eval_count"],
            evidence["policy_tenant"],
            evidence["policy_version"],
        ),
    )


def gate_evidence_counts(connection, version: dict[str, Any]) -> dict[str, Any]:
    params = {
        "tenant_id": version.get("tenant_id"),
        "project": version["project"],
        "environment": version["environment"],
        "application_name": version["application_name"],
        "workflow_name": version["workflow_name"],
        "prompt_version": version.get("prompt_version"),
        "artifact_ref": version.get("artifact_ref"),
    }
    # the governance policy's entry for this environment decides what the gate
    # demands; it can only tighten. attestation is required when the policy says
    # so OR the tenant registered attestation keys (the pre-policy behavior,
    # which a policy can never switch off)
    from .policy_engine import resolve_gate_policy

    requirements = resolve_gate_policy(connection, version.get("tenant_id"), version["environment"])
    require_attested = bool(requirements["require_attested_evals"]) or tenant_requires_attestation(
        version.get("tenant_id"), connection
    )
    risk_count = count_scoped(connection, "risk_findings", "status IN ('open', 'mitigation_required')", params)
    missing_control_count = count_scoped(connection, "control_assessments", "status = 'missing'", params)
    material_change_count = count_scoped(connection, "change_events", "status = 'open'", params)
    prompt_version = find_prompt_version(connection, params)
    passing_eval_count = count_passing_eval_evidence(connection, params, require_attested)
    return {
        "risk_count": risk_count,
        "missing_control_count": missing_control_count,
        "material_change_count": material_change_count,
        "prompt_version_id": prompt_version.get("prompt_version_id") if prompt_version else None,
        "prompt_evidence_status": "linked" if prompt_version else "missing",
        "passing_eval_count": passing_eval_count,
        "require_attested_evals": require_attested,
        "max_open_material_changes": int(requirements["max_open_material_changes"]),
        "policy_tenant": requirements["policy_tenant"],
        "policy_version": requirements["policy_version"],
    }


def find_prompt_version(connection, params: dict[str, Any]) -> dict[str, Any] | None:
    if not params.get("prompt_version"):
        return None
    row = connection.execute(
        """
        SELECT *
        FROM prompt_versions
        WHERE project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND workflow_name = :workflow_name
          AND version = :prompt_version
          AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)
        ORDER BY observed_at DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    return None if row is None else dict(row)


def count_passing_eval_evidence(connection, params: dict[str, Any], require_attested: bool | None = None) -> int:
    rows = connection.execute(
        """
        SELECT attributes
        FROM governance_observed_events
        WHERE entity_type = 'eval.result'
          AND project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND workflow_name = :workflow_name
          AND status = 'success'
          AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)
        """,
        params,
    ).fetchall()
    # once a tenant has an attestation key (or its governance policy demands
    # attestation for this environment), only evals whose signature verified at
    # ingestion count; a self-reported passed: true no longer satisfies
    if require_attested is None:
        require_attested = tenant_requires_attestation(params.get("tenant_id"), connection)
    version_artifact = params.get("artifact_ref")
    version_prompt = params.get("prompt_version")
    count = 0
    for row in rows:
        try:
            attrs = json.loads(row["attributes"])
        except json.JSONDecodeError:
            attrs = {}
        if attrs.get("passed") is not True:
            continue
        if require_attested and attrs.get("attested") is not True:
            continue
        # the eval must be about this release: prefer artifact_ref (what the
        # attestation signs), fall back to prompt_version. neither or a mismatch
        # doesn't count, so an earlier version's evals can't pass an untested build
        eval_artifact = attrs.get("artifact_ref")
        eval_prompt = attrs.get("prompt_version")
        if eval_artifact is not None:
            if version_artifact is None or eval_artifact != version_artifact:
                continue
        elif eval_prompt is not None:
            if version_prompt is None or eval_prompt != version_prompt:
                continue
        else:
            continue  # names neither artifact nor prompt version, not bindable
        count += 1
    return count


def count_scoped(connection, table: str, status_clause: str, params: dict[str, Any]) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {table}
        WHERE project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND ({status_clause})
          AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)
        """,
        params,
    ).fetchone()
    return int(row["count"])


def set_deployment_gate_status(gate_id: str, status: str, actor_ref: str, rationale: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone()
        if row is None:
            raise RecordNotFound("deployment gate not found")
        gate = dict(row)
        # a gate decision is terminal: once a human approves or rejects this
        # version's gate it cannot be silently re-decided (which would let a
        # second admin flip an approval to a rejection, or re-approve a rejected
        # release, with no distinct action). new telemetry already preserves a
        # decided status; a superseding build gets its own gate
        if gate["gate_status"] in {"approved", "rejected"}:
            raise DomainError(f"deployment gate has already been {gate['gate_status']} and cannot be decided again")
        evidence = None
        if status == "approved":
            # recompute from current state: accepting a finding or waiving a
            # control does not touch the stored counts, only ingestion refreshes
            # them, so approving on the stored values would ignore the very
            # remediation this gate asks for. requirements come from the active
            # governance policy for this environment (which can only tighten)
            evidence = live_gate_evidence(connection, gate)
            if evidence["prompt_evidence_status"] != "linked" or int(evidence["passing_eval_count"] or 0) == 0:
                if evidence.get("require_attested_evals"):
                    raise ValueError(
                        "deployment gate requires a linked prompt version and attested passing eval evidence "
                        "bound to this version (the governance policy requires attestation for this environment)"
                    )
                raise ValueError("deployment gate requires a linked prompt version and passing eval evidence bound to this version")
                raise DomainError("deployment gate requires a linked prompt version and passing eval evidence bound to this version")
            if int(evidence["risk_count"] or 0) > 0:
                raise DomainError("deployment gate cannot be approved while risk findings are open; mitigate or accept them first")
            if int(evidence["missing_control_count"] or 0) > 0:
                raise ValueError("deployment gate cannot be approved while controls are missing evidence")
            if int(evidence["material_change_count"] or 0) > int(evidence.get("max_open_material_changes") or 0):
                raise ValueError("deployment gate cannot be approved while material changes are unreviewed; review or accept them first")
                raise DomainError("deployment gate cannot be approved while controls are missing evidence")
            if int(evidence["material_change_count"] or 0) > 0:
                raise DomainError("deployment gate cannot be approved while material changes are unreviewed; review or accept them first")
        if not (rationale or "").strip():
            raise DomainError("a decision rationale is required")
        if evidence is not None:
            # the decision is recorded against the evidence that was actually
            # checked, including the policy version whose rules governed it
            connection.execute(
                """
                UPDATE deployment_approval_gates
                SET risk_count = ?, missing_control_count = ?, material_change_count = ?,
                    prompt_version_id = ?, prompt_evidence_status = ?, passing_eval_count = ?,
                    policy_tenant = ?, policy_version = ?,
                    required_reason = ?
                WHERE gate_id = ?
                """,
                (
                    evidence["risk_count"],
                    evidence["missing_control_count"],
                    evidence["material_change_count"],
                    evidence["prompt_version_id"],
                    evidence["prompt_evidence_status"],
                    evidence["passing_eval_count"],
                    evidence["policy_tenant"],
                    evidence["policy_version"],
                    gate_required_reason(connection, evidence, gate.get("tenant_id")),
                    gate_id,
                ),
            )
        connection.execute(
            """
            UPDATE deployment_approval_gates
            SET gate_status = ?, actor_ref = ?, rationale = ?, decided_at = datetime('now'), updated_at = datetime('now')
            WHERE gate_id = ?
            """,
            (status, actor_ref, rationale, gate_id),
        )
        return dict(connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone())


def gate_deployer(version_id: str) -> str | None:
    """user who deployed the gated version; maker-checker: they can't approve it"""
    with connect() as connection:
        row = connection.execute("SELECT deployed_by FROM deployment_versions WHERE version_id = ?", (version_id,)).fetchone()
    return None if row is None else row["deployed_by"]


def load_deployment_gate(gate_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone()
    if row is None:
        raise RecordNotFound("deployment gate not found")
    return dict(row)




def list_deployments(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("governance_deployments", tenant_id=tenant_id, project=project, environment=environment, order_by="last_seen")


def list_deployment_versions(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("deployment_versions", tenant_id=tenant_id, project=project, environment=environment, order_by="observed_at")


def list_deployment_gates(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    # enrich each gate with the version and artifact it gates, so callers can
    # see which build a decision applies to
    clauses: list[str] = ["1=1"]
    params: dict[str, Any] = {}
    if tenant_id:
        clauses.append("g.tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if project:
        clauses.append("g.project = :project")
        params["project"] = project
    if environment:
        clauses.append("g.environment = :environment")
        params["environment"] = environment
    window = ""
    if limit is not None:
        window = " LIMIT :limit OFFSET :offset"
        params.update({"limit": limit, "offset": offset})
    with connect() as connection:
        rows = connection.execute(
            f"""
            SELECT g.*, v.version AS version, v.artifact_ref AS artifact_ref
            FROM deployment_approval_gates g
            LEFT JOIN deployment_versions v ON v.version_id = g.version_id
            WHERE {' AND '.join(clauses)}
            ORDER BY g.updated_at DESC{window}
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def find_gate_for_release(tenant_id: str, deployment_id: str, version: str) -> dict[str, Any] | None:
    """gate for a (deployment, version) pair, tenant-bound so the CI lookup
    never crosses the key's org"""
    with connect() as connection:
        row = connection.execute(
            """
            SELECT g.gate_id, g.gate_status, g.required_reason, g.application_name, g.workflow_name,
                   g.actor_ref, g.rationale, g.decided_at, g.updated_at, v.version, v.deployment_id
            FROM deployment_approval_gates g
            JOIN deployment_versions v ON v.version_id = g.version_id
            WHERE v.deployment_id = ? AND v.version = ? AND g.tenant_id = ?
            ORDER BY v.observed_at DESC
            LIMIT 1
            """,
            (deployment_id, version, tenant_id),
        ).fetchone()
    return None if row is None else dict(row)


def count_deployment_gates(
    *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None
) -> int:
    return count_scoped_rows("deployment_approval_gates", tenant_id=tenant_id, project=project, environment=environment)

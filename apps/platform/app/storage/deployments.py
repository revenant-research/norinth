from __future__ import annotations

import json
from typing import Any

from . import db
from .attestation_keys import tenant_requires_attestation
from .entities import entity_id
from .raw_events import connect


def init_deployments() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_deployments (
                deployment_id TEXT PRIMARY KEY,
                tenant_id TEXT,
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
                last_seen TEXT NOT NULL
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
    metadata = attrs.get("metadata") or {}
    deployment_id = attrs["deployment_id"]
    version = attrs["version"]
    application_name = metadata.get("application_name")
    workflow_name = metadata.get("workflow_name")
    if not application_name or not workflow_name:
        return
    status = attrs.get("deployment_status") or event.get("status", "observed")
    version_id = entity_id("deployment-version", metadata.get("tenant_id"), event["project"], event["environment"], deployment_id, version)
    connection.execute(
        """
        INSERT INTO governance_deployments (
            deployment_id, tenant_id, project, environment, application_name, workflow_name,
            current_version, current_status, provider, model, artifact_ref, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(deployment_id) DO UPDATE SET
            current_version=excluded.current_version,
            current_status=excluded.current_status,
            provider=excluded.provider,
            model=excluded.model,
            artifact_ref=excluded.artifact_ref,
            last_seen=excluded.last_seen
        """,
        (
            deployment_id,
            metadata.get("tenant_id"),
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
            metadata.get("tenant_id"),
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


def refresh_deployment_gates() -> None:
    with connect() as connection:
        versions = connection.execute("SELECT * FROM deployment_versions ORDER BY observed_at DESC").fetchall()
        for version in versions:
            upsert_deployment_gate(connection, dict(version))


def upsert_deployment_gate(connection, version: dict[str, Any]) -> None:
    evidence = gate_evidence_counts(connection, version)
    gate_id = entity_id("deployment-gate", version["version_id"])
    existing = connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone()
    current_status = existing["gate_status"] if existing else None
    # A gate is NEVER auto-approved (audit C-2). Undecided gates stay
    # pending_review until a human approves or rejects them through the guarded
    # /approve|/reject endpoints; an existing human decision is preserved. Whether
    # a gate is approvable (has linked prompt + passing eval and no open blockers)
    # is enforced at approval time by set_deployment_gate_status, and the blocking
    # reasons below tell the reviewer what is still outstanding.
    gate_status = current_status if current_status in {"approved", "rejected"} else "pending_review"
    reason_parts = []
    if evidence["risk_count"]:
        reason_parts.append(f"{evidence['risk_count']} open risk findings")
    if evidence["missing_control_count"]:
        reason_parts.append(f"{evidence['missing_control_count']} missing controls")
    if evidence["material_change_count"]:
        reason_parts.append(f"{evidence['material_change_count']} material changes")
    if evidence["prompt_evidence_status"] != "linked":
        reason_parts.append("missing linked prompt version")
    if evidence["passing_eval_count"] == 0:
        reason_parts.append(
            "missing attested passing eval evidence"
            if tenant_requires_attestation(version.get("tenant_id"), connection)
            else "missing passing eval evidence"
        )
    required_reason = "; ".join(reason_parts) if reason_parts else "No blocking governance evidence detected"
    connection.execute(
        """
        INSERT INTO deployment_approval_gates (
            gate_id, deployment_id, version_id, tenant_id, project, environment, application_name, workflow_name,
            gate_status, required_reason, risk_count, missing_control_count, material_change_count,
            prompt_version_id, prompt_evidence_status, passing_eval_count, actor_ref, rationale, submitted_at, decided_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, datetime('now'), NULL, datetime('now'))
        ON CONFLICT(gate_id) DO UPDATE SET
            gate_status=excluded.gate_status,
            required_reason=excluded.required_reason,
            risk_count=excluded.risk_count,
            missing_control_count=excluded.missing_control_count,
            material_change_count=excluded.material_change_count,
            prompt_version_id=excluded.prompt_version_id,
            prompt_evidence_status=excluded.prompt_evidence_status,
            passing_eval_count=excluded.passing_eval_count,
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
        ),
    )


def gate_evidence_counts(connection, version: dict[str, Any]) -> dict[str, int]:
    params = {
        "tenant_id": version.get("tenant_id"),
        "project": version["project"],
        "environment": version["environment"],
        "application_name": version["application_name"],
        "workflow_name": version["workflow_name"],
        "prompt_version": version.get("prompt_version"),
    }
    risk_count = count_scoped(connection, "risk_findings", "status IN ('open', 'mitigation_required')", params)
    missing_control_count = count_scoped(connection, "control_assessments", "status = 'missing'", params)
    material_change_count = count_scoped(connection, "change_events", "status = 'open'", params)
    prompt_version = find_prompt_version(connection, params)
    passing_eval_count = count_passing_eval_evidence(connection, params)
    return {
        "risk_count": risk_count,
        "missing_control_count": missing_control_count,
        "material_change_count": material_change_count,
        "prompt_version_id": prompt_version.get("prompt_version_id") if prompt_version else None,
        "prompt_evidence_status": "linked" if prompt_version else "missing",
        "passing_eval_count": passing_eval_count,
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


def count_passing_eval_evidence(connection, params: dict[str, Any]) -> int:
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
    # Once an organization has registered an attestation key, only evals whose
    # Ed25519 signature verified at ingestion count as gate evidence; a
    # self-reported ``passed: true`` no longer satisfies the gate (C-2
    # hardening, roadmap #20).
    require_attested = tenant_requires_attestation(params.get("tenant_id"), connection)
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
            raise ValueError("deployment gate not found")
        gate = dict(row)
        if status == "approved" and (gate.get("prompt_evidence_status") != "linked" or int(gate.get("passing_eval_count") or 0) == 0):
            raise ValueError("deployment gate requires linked prompt version and passing eval evidence")
        connection.execute(
            """
            UPDATE deployment_approval_gates
            SET gate_status = ?, actor_ref = ?, rationale = ?, decided_at = datetime('now'), updated_at = datetime('now')
            WHERE gate_id = ?
            """,
            (status, actor_ref, rationale, gate_id),
        )
        return dict(connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone())


def load_deployment_gate(gate_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT * FROM deployment_approval_gates WHERE gate_id = ?", (gate_id,)).fetchone()
    if row is None:
        raise ValueError("deployment gate not found")
    return dict(row)


def scoped_rows(table: str, *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None, order_by: str = "updated_at") -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if tenant_id:
        clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if project:
        clauses.append("project = :project")
        params["project"] = project
    if environment:
        clauses.append("environment = :environment")
        params["environment"] = environment
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as connection:
        rows = connection.execute(f"SELECT * FROM {table} {where} ORDER BY {order_by} DESC", params).fetchall()
    return [dict(row) for row in rows]


def list_deployments(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("governance_deployments", tenant_id=tenant_id, project=project, environment=environment, order_by="last_seen")


def list_deployment_versions(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("deployment_versions", tenant_id=tenant_id, project=project, environment=environment, order_by="observed_at")


def list_deployment_gates(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("deployment_approval_gates", tenant_id=tenant_id, project=project, environment=environment)

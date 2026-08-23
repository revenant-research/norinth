from __future__ import annotations

import json
from typing import Any

from .entities import entity_id
from .raw_events import connect


def init_incidents() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_incidents (
                incident_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT '',
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                description_summary TEXT NOT NULL,
                detected_by TEXT,
                trace_id TEXT NOT NULL,
                impacted_trace_id TEXT,
                provider TEXT,
                model TEXT,
                risk_count INTEGER NOT NULL,
                missing_control_count INTEGER NOT NULL,
                deployment_id TEXT,
                deployment_version_id TEXT,
                deployment_gate_id TEXT,
                actor_ref TEXT,
                resolution_rationale TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                closed_at TEXT,
                PRIMARY KEY (tenant_id, project, environment, incident_id)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_governance_incidents_scope ON governance_incidents(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_governance_incidents_status ON governance_incidents(status)")


def process_incident_events(events: list[dict[str, Any]]) -> None:
    with connect() as connection:
        for event in events:
            if event["type"] == "incident.event":
                upsert_incident_event(connection, event)


def upsert_incident_event(connection, event: dict[str, Any]) -> None:
    attrs = event.get("attributes") or {}
    metadata = attrs.get("metadata") or {}
    application_name = metadata.get("application_name")
    workflow_name = metadata.get("workflow_name")
    if not application_name or not workflow_name:
        return

    scope = {
        "tenant_id": metadata.get("tenant_id"),
        "project": event["project"],
        "environment": event["environment"],
        "application_name": application_name,
        "workflow_name": workflow_name,
    }
    deployment = latest_deployment_evidence(connection, scope)
    evidence = incident_evidence_counts(connection, scope)
    incident_id = attrs.get("incident_id") or entity_id("incident", event["trace_id"], event["span_id"])
    incident_tenant = scope["tenant_id"] or ""
    description_summary = json.dumps(attrs.get("description") or {}, sort_keys=True)
    status = attrs.get("incident_status") or event.get("status", "open")
    is_new = connection.execute(
        "SELECT 1 FROM governance_incidents WHERE incident_id = ? AND tenant_id = ? AND project = ? AND environment = ?",
        (incident_id, incident_tenant, event["project"], event["environment"]),
    ).fetchone() is None
    connection.execute(
        """
        INSERT INTO governance_incidents (
            incident_id, tenant_id, project, environment, application_name, workflow_name,
            title, severity, status, description_summary, detected_by, trace_id, impacted_trace_id,
            provider, model, risk_count, missing_control_count, deployment_id, deployment_version_id,
            deployment_gate_id, actor_ref, resolution_rationale, first_seen, last_seen, closed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL)
        ON CONFLICT(tenant_id, project, environment, incident_id) DO UPDATE SET
            title=excluded.title,
            severity=excluded.severity,
            status=CASE
                WHEN governance_incidents.status = 'closed' THEN governance_incidents.status
                ELSE excluded.status
            END,
            description_summary=excluded.description_summary,
            detected_by=excluded.detected_by,
            impacted_trace_id=excluded.impacted_trace_id,
            provider=excluded.provider,
            model=excluded.model,
            risk_count=excluded.risk_count,
            missing_control_count=excluded.missing_control_count,
            deployment_id=excluded.deployment_id,
            deployment_version_id=excluded.deployment_version_id,
            deployment_gate_id=excluded.deployment_gate_id,
            last_seen=excluded.last_seen
        """,
        (
            incident_id,
            incident_tenant,
            scope["project"],
            scope["environment"],
            scope["application_name"],
            scope["workflow_name"],
            attrs.get("title") or event.get("name") or incident_id,
            attrs.get("severity") or "unclassified",
            status,
            description_summary,
            attrs.get("detected_by"),
            event["trace_id"],
            attrs.get("impacted_trace_id"),
            attrs.get("provider"),
            attrs.get("model"),
            evidence["risk_count"],
            evidence["missing_control_count"],
            deployment.get("deployment_id") if deployment else None,
            deployment.get("version_id") if deployment else None,
            deployment.get("gate_id") if deployment else None,
            event["timestamp"],
            event["timestamp"],
        ),
    )
    if is_new and status != "closed":
        from app.services.notifications import emit, public_base_url

        emit(
            connection,
            tenant_id=scope["tenant_id"],
            event_type="incident.opened",
            subject=f"Incident opened: {attrs.get('title') or event.get('name') or incident_id}",
            text=f"Severity {attrs.get('severity') or 'unclassified'} incident on {application_name} / {workflow_name}, reported by {attrs.get('detected_by') or 'the SDK'}.",
            data={"incident_id": incident_id, "application_name": application_name, "workflow_name": workflow_name, "severity": attrs.get("severity")},
            to_roles=["org_admin", "risk_owner", "governance_admin"],
            link=f"{public_base_url()}/#incident/{incident_id}",
        )


def latest_deployment_evidence(connection, scope: dict[str, Any]) -> dict[str, Any] | None:
    return row_to_dict(
        connection.execute(
            """
            SELECT deployment_versions.deployment_id, deployment_versions.version_id, deployment_approval_gates.gate_id
            FROM deployment_versions
            LEFT JOIN deployment_approval_gates
              ON deployment_approval_gates.version_id = deployment_versions.version_id
            WHERE deployment_versions.project = :project
              AND deployment_versions.environment = :environment
              AND deployment_versions.application_name = :application_name
              AND deployment_versions.workflow_name = :workflow_name
              AND ((:tenant_id IS NULL AND deployment_versions.tenant_id IS NULL) OR deployment_versions.tenant_id = :tenant_id)
            ORDER BY deployment_versions.observed_at DESC
            LIMIT 1
            """,
            scope,
        ).fetchone()
    )


def incident_evidence_counts(connection, scope: dict[str, Any]) -> dict[str, int]:
    risk_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM risk_findings
        WHERE project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND status IN ('open', 'mitigation_required')
          AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)
        """,
        scope,
    ).fetchone()
    control_row = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM control_assessments
        WHERE project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND status = 'missing'
          AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)
        """,
        scope,
    ).fetchone()
    return {"risk_count": int(risk_row["count"]), "missing_control_count": int(control_row["count"])}


def set_incident_status(incident_id: str, status: str, actor_ref: str, rationale: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT * FROM governance_incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if row is None:
            raise ValueError("incident not found")
        connection.execute(
            """
            UPDATE governance_incidents
            SET status = ?, actor_ref = ?, resolution_rationale = ?, closed_at = CASE WHEN ? = 'closed' THEN datetime('now') ELSE closed_at END, last_seen = datetime('now')
            WHERE incident_id = ?
            """,
            (status, actor_ref, rationale, status, incident_id),
        )
        return dict(connection.execute("SELECT * FROM governance_incidents WHERE incident_id = ?", (incident_id,)).fetchone())


def load_incident(incident_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT * FROM governance_incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        raise ValueError("incident not found")
    return dict(row)


def list_incidents(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
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
        rows = connection.execute(
            f"""
            SELECT
                governance_incidents.*,
                (
                    SELECT owner_ref
                    FROM owner_assignments
                    WHERE owner_assignments.subject_type = 'incident'
                      AND owner_assignments.subject_name = governance_incidents.incident_id
                    ORDER BY updated_at DESC
                    LIMIT 1
                ) AS owner_ref,
                (
                    SELECT status
                    FROM owner_assignments
                    WHERE owner_assignments.subject_type = 'incident'
                      AND owner_assignments.subject_name = governance_incidents.incident_id
                    ORDER BY updated_at DESC
                    LIMIT 1
                ) AS owner_status
            FROM governance_incidents
            {where}
            ORDER BY last_seen DESC
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def row_to_dict(row) -> dict[str, Any] | None:
    return None if row is None else dict(row)

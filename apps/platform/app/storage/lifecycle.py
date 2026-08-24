from __future__ import annotations

from hashlib import sha256
from typing import Any

from .entities import as_object, decode_json, encode_json, entity_id
from .raw_events import connect

MATERIAL_FIELDS = {
    "agents",
    "eval_thresholds",
    "evals",
    "guardrails",
    "models",
    "providers",
    "retrievers",
    "tools",
    "workflows",
}

HIGH_RISK_FIELDS = {"eval_thresholds", "guardrails", "models", "providers", "tools"}


def init_lifecycle() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS lifecycle_fingerprints (
                fingerprint_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                fingerprint_payload TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS change_events (
                change_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                change_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                previous_hash TEXT,
                current_hash TEXT NOT NULL,
                previous_payload TEXT,
                current_payload TEXT NOT NULL,
                changed_fields TEXT NOT NULL,
                evidence_trace_ids TEXT NOT NULL,
                rationale TEXT NOT NULL,
                detected_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_tasks (
                task_id TEXT PRIMARY KEY,
                change_id TEXT NOT NULL,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                title TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_lifecycle_fingerprints_scope ON lifecycle_fingerprints(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_change_events_scope ON change_events(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_review_tasks_scope ON review_tasks(tenant_id, project, environment)")


def refresh_lifecycle_state(scopes: list[dict[str, Any]] | None = None) -> None:
    """recompute change fingerprints; scopes limits to the apps an ingest
    touched, None does everything"""
    with connect() as connection:
        applications = _applications_in_scope(connection, scopes)
        for application in applications:
            app_context = dict(application)
            events = list_application_events(connection, app_context)
            for fingerprint in build_fingerprints(app_context, events):
                upsert_fingerprint(connection, app_context, fingerprint)


def _applications_in_scope(connection, scopes: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT DISTINCT tenant_id, project, environment, application_name FROM governance_applications"
    ).fetchall()
    if scopes is None:
        return [dict(row) for row in rows]
    wanted = {(s.get("tenant_id"), s["project"], s["environment"], s["application_name"]) for s in scopes}
    return [
        dict(row)
        for row in rows
        if (row["tenant_id"], row["project"], row["environment"], row["application_name"]) in wanted
    ]


def list_application_events(connection, app_context: dict[str, Any]) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT raw_event FROM sdk_events
        WHERE project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND (
            (:tenant_id IS NULL AND tenant_id IS NULL)
            OR tenant_id = :tenant_id
          )
        ORDER BY id
        """,
        app_context,
    ).fetchall()
    return [decode_json(row["raw_event"], {}) for row in rows]


def build_fingerprints(app_context: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    app_payload = fingerprint_payload(events)
    fingerprints = [
        {
            "subject_type": "application",
            "subject_name": app_context["application_name"],
            "payload": app_payload,
            "trace_ids": trace_ids(events),
            "observed_at": latest_timestamp(events),
        }
    ]
    for workflow_name in sorted(app_payload["workflows"]):
        workflow_events = [
            event
            for event in events
            if as_object(as_object(event.get("attributes")).get("metadata")).get("workflow_name") == workflow_name
        ]
        fingerprints.append(
            {
                "subject_type": "workflow",
                "subject_name": workflow_name,
                "payload": fingerprint_payload(workflow_events),
                "trace_ids": trace_ids(workflow_events),
                "observed_at": latest_timestamp(workflow_events),
            }
        )
    return fingerprints


def fingerprint_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agents": sorted(attribute_values(events, "agent_name")),
        "eval_thresholds": sorted(
            f"{attrs.get('eval_name')}:{attrs.get('threshold')}"
            for attrs in event_attributes_for_type(events, "eval.result")
            if attrs.get("eval_name") and attrs.get("threshold") is not None
        ),
        "evals": sorted(attribute_values(events, "eval_name")),
        "guardrails": sorted(attribute_values(events, "guardrail_name")),
        "models": sorted(
            f"{attrs.get('provider')}:{attrs.get('model')}"
            for attrs in event_attributes_for_type(events, "model.call")
            if attrs.get("provider") and attrs.get("model")
        ),
        "providers": sorted(attribute_values(events, "provider")),
        "retrievers": sorted(attribute_values(events, "retriever")),
        "tools": sorted(attribute_values(events, "tool_name")),
        "workflows": sorted(metadata_values(events, "workflow_name")),
    }


def event_attributes_for_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [event.get("attributes") or {} for event in events if event.get("type") == event_type]


def attribute_values(events: list[dict[str, Any]], field: str) -> set[str]:
    values = set()
    for event in events:
        value = (event.get("attributes") or {}).get(field)
        if value not in (None, ""):
            values.add(str(value))
    return values


def metadata_values(events: list[dict[str, Any]], field: str) -> set[str]:
    values = set()
    for event in events:
        metadata = as_object(as_object(event.get("attributes")).get("metadata"))
        value = metadata.get(field)
        if value not in (None, ""):
            values.add(str(value))
    return values


def trace_ids(events: list[dict[str, Any]]) -> list[str]:
    return sorted({event["trace_id"] for event in events if event.get("trace_id")})


def latest_timestamp(events: list[dict[str, Any]]) -> str:
    return max((event["timestamp"] for event in events if event.get("timestamp")), default="")


def hash_payload(payload: dict[str, Any]) -> str:
    return sha256(encode_json(payload).encode("utf-8")).hexdigest()


def upsert_fingerprint(connection, app_context: dict[str, Any], fingerprint: dict[str, Any]) -> None:
    fingerprint_hash = hash_payload(fingerprint["payload"])
    fingerprint_id = entity_id(
        "lifecycle-fingerprint",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        fingerprint["subject_type"],
        fingerprint["subject_name"],
    )
    existing = connection.execute(
        "SELECT * FROM lifecycle_fingerprints WHERE fingerprint_id = ?",
        (fingerprint_id,),
    ).fetchone()
    if existing and existing["fingerprint_hash"] != fingerprint_hash:
        previous_payload = decode_json(existing["fingerprint_payload"], {})
        changed_fields = changed_material_fields(previous_payload, fingerprint["payload"])
        if changed_fields:
            insert_change_event(
                connection,
                app_context,
                fingerprint,
                previous_hash=existing["fingerprint_hash"],
                current_hash=fingerprint_hash,
                previous_payload=previous_payload,
                changed_fields=changed_fields,
            )
    observed_at = fingerprint["observed_at"]
    connection.execute(
        """
        INSERT INTO lifecycle_fingerprints (
            fingerprint_id, tenant_id, project, environment, application_name, subject_type,
            subject_name, fingerprint_hash, fingerprint_payload, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint_id) DO UPDATE SET
            fingerprint_hash=excluded.fingerprint_hash,
            fingerprint_payload=excluded.fingerprint_payload,
            last_seen=excluded.last_seen
        """,
        (
            fingerprint_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            fingerprint["subject_type"],
            fingerprint["subject_name"],
            fingerprint_hash,
            encode_json(fingerprint["payload"]),
            observed_at,
            observed_at,
        ),
    )


def changed_material_fields(previous_payload: dict[str, Any], current_payload: dict[str, Any]) -> list[str]:
    return sorted(
        field
        for field in MATERIAL_FIELDS
        if previous_payload.get(field, []) != current_payload.get(field, [])
    )


def insert_change_event(
    connection,
    app_context: dict[str, Any],
    fingerprint: dict[str, Any],
    *,
    previous_hash: str,
    current_hash: str,
    previous_payload: dict[str, Any],
    changed_fields: list[str],
) -> None:
    change_id = entity_id(
        "change-event",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        fingerprint["subject_type"],
        fingerprint["subject_name"],
        previous_hash,
        current_hash,
    )
    severity = "High" if HIGH_RISK_FIELDS.intersection(changed_fields) else "Medium"
    rationale = f"Material {fingerprint['subject_type']} change detected in: {', '.join(changed_fields)}"
    connection.execute(
        """
        INSERT OR IGNORE INTO change_events (
            change_id, tenant_id, project, environment, application_name, subject_type, subject_name,
            change_type, severity, status, previous_hash, current_hash, previous_payload,
            current_payload, changed_fields, evidence_trace_ids, rationale, detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            change_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            fingerprint["subject_type"],
            fingerprint["subject_name"],
            "material_change",
            severity,
            "open",
            previous_hash,
            current_hash,
            encode_json(previous_payload),
            encode_json(fingerprint["payload"]),
            encode_json(changed_fields),
            encode_json(fingerprint["trace_ids"]),
            rationale,
            fingerprint["observed_at"],
        ),
    )
    upsert_review_task(connection, app_context, change_id, fingerprint, severity, rationale)


def upsert_review_task(
    connection,
    app_context: dict[str, Any],
    change_id: str,
    fingerprint: dict[str, Any],
    severity: str,
    rationale: str,
) -> None:
    task_id = entity_id("review-task", change_id)
    priority = "high" if severity == "High" else "medium"
    title = f"Review {fingerprint['subject_type']} change: {fingerprint['subject_name']}"
    connection.execute(
        """
        INSERT INTO review_tasks (
            task_id, change_id, tenant_id, project, environment, application_name, task_type,
            status, priority, title, rationale, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        ON CONFLICT(task_id) DO UPDATE SET
            status=review_tasks.status,
            priority=excluded.priority,
            title=excluded.title,
            rationale=excluded.rationale,
            updated_at=datetime('now')
        """,
        (
            task_id,
            change_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            "material_change_review",
            "open",
            priority,
            title,
            rationale,
        ),
    )


def list_change_events(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = scoped_query(
            connection,
            "change_events",
            tenant_id=tenant_id,
            project=project,
            environment=environment,
            order_by="detected_at",
        )
    return [
        {
            **row,
            "previous_payload": decode_json(row["previous_payload"], {}),
            "current_payload": decode_json(row["current_payload"], {}),
            "changed_fields": decode_json(row["changed_fields"], []),
            "evidence_trace_ids": decode_json(row["evidence_trace_ids"], []),
        }
        for row in rows
    ]


def list_review_tasks(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    with connect() as connection:
        return scoped_query(
            connection,
            "review_tasks",
            tenant_id=tenant_id,
            project=project,
            environment=environment,
            order_by="updated_at",
        )


def scoped_query(
    connection,
    table: str,
    *,
    tenant_id: str | None,
    project: str | None,
    environment: str | None,
    order_by: str,
) -> list[dict[str, Any]]:
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
    rows = connection.execute(f"SELECT * FROM {table} {where} ORDER BY {order_by} DESC", params).fetchall()
    return [dict(row) for row in rows]

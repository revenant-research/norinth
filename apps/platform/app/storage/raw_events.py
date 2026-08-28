from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.services import secrets as secret_store

from . import db

# the raw event body can carry prompt/response content (phi with content capture
# on), so the raw_event column is encrypted at rest whenever a secret key is
# configured, while the extracted governance columns stay queryable in plaintext.
# reads decrypt transparently and legacy plaintext rows pass through, so this
# needs no migration in either direction
_RAW_EVENT_AAD = "sdk_event"


def _encrypt_raw_events() -> bool:
    """whether to encrypt raw event bodies at rest

    defaults to on wherever a secret key is configured, so a real install protects
    captured content without having to find a flag first. keyless dev installs
    keep storing plaintext (secret_store.encrypt fails closed without a key), and
    NORINTH_ENCRYPT_RAW_EVENTS=0 is an explicit opt-out for an operator who has a
    key but wants the column queryable
    """
    setting = os.getenv("NORINTH_ENCRYPT_RAW_EVENTS")
    if setting is not None and setting.strip() != "":
        return setting.strip().lower() in {"1", "true", "yes"}
    return secret_store.encryption_enabled()


def serialize_raw_event(event: dict[str, Any]) -> str:
    payload = json.dumps(event)
    if _encrypt_raw_events():
        return secret_store.encrypt(payload, associated_data=_RAW_EVENT_AAD)
    return payload


def deserialize_raw_event(stored: str) -> dict[str, Any]:
    # decrypt returns plaintext unchanged, so this handles both encrypted and
    # legacy-plaintext rows
    return json.loads(secret_store.decrypt(stored, associated_data=_RAW_EVENT_AAD))


def _as_object(value):
    return value if isinstance(value, dict) else {}

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "norinth.sqlite3"


def database_path() -> Path:
    return db.database_path()


def connect():
    """open a connection to the configured backend; see storage/db.py"""
    return db.connect()


def init_storage() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sdk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                environment TEXT NOT NULL,
                project TEXT NOT NULL,
                system TEXT,
                name TEXT,
                status TEXT NOT NULL,
                duration_ms REAL,
                tenant_id TEXT,
                user_id TEXT,
                application_name TEXT,
                workflow_name TEXT,
                use_case TEXT,
                model_purpose TEXT,
                provider TEXT,
                model TEXT,
                operation TEXT,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                raw_event TEXT NOT NULL,
                ingested_at TEXT
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_trace ON sdk_events(trace_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_tenant ON sdk_events(tenant_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_project_env ON sdk_events(project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_type ON sdk_events(event_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_application ON sdk_events(application_name)")
        # composite index for the per-application evidence scans run on every
        # ingest (governance_policy / lifecycle recompute)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sdk_events_app_scope "
            "ON sdk_events(project, environment, application_name, tenant_id)"
        )
        # idempotency: a retried batch re-sends the same (trace_id, span_id)
        # spans; a unique index plus INSERT OR IGNORE prevents double-counting
        # guarded because a legacy db may already hold duplicates
        try:
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_sdk_events_span_tenant "
                "ON sdk_events(tenant_id, trace_id, span_id)"
            )
        except db.IntegrityError:
            pass


# columns written per event; ingested_at is stamped by SQL, not a bound param
_EVENT_COLUMNS = [
    "event_type", "schema_version", "trace_id", "span_id", "parent_span_id", "timestamp", "service",
    "environment", "project", "system", "name", "status", "duration_ms", "tenant_id", "user_id",
    "application_name", "workflow_name", "use_case", "model_purpose", "provider", "model",
    "operation", "input_tokens", "output_tokens", "raw_event",
]
# keep each multi-row INSERT well under postgres's 65535 bound-parameter limit
_INSERT_CHUNK = 500


def insert_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """insert events idempotently, returning the events actually inserted

    INSERT OR IGNORE against the unique (tenant_id, trace_id, span_id) index so a
    retried batch does not create duplicate rows, and RETURNING reports the rows
    this statement actually inserted. Because the database (not a pre-check)
    decides what was inserted, two concurrent identical batches each learn the
    truth: exactly one of them inserts a given event. Only the newly inserted
    events are returned, so the caller projects each event exactly once — a retry
    that inserts nothing must not re-increment metrics.
    """
    rows = [event_to_row(event) for event in events]
    if not rows:
        return []
    column_sql = ", ".join(_EVENT_COLUMNS)
    row_placeholder = "(" + ", ".join("?" for _ in _EVENT_COLUMNS) + ", datetime('now'))"
    inserted_keys: set[tuple] = set()
    with connect() as connection:
        for start in range(0, len(rows), _INSERT_CHUNK):
            chunk = rows[start : start + _INSERT_CHUNK]
            values_sql = ", ".join(row_placeholder for _ in chunk)
            params = [row[column] for row in chunk for column in _EVENT_COLUMNS]
            returned = connection.execute(
                f"INSERT OR IGNORE INTO sdk_events ({column_sql}, ingested_at) "
                f"VALUES {values_sql} RETURNING tenant_id, trace_id, span_id",
                tuple(params),
            ).fetchall()
            for row in returned:
                inserted_keys.add((row["tenant_id"], row["trace_id"], row["span_id"]))
    # return the first event for each key the database actually inserted, in
    # order; a within-batch duplicate maps to one returned key, so emit it once
    inserted: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for event, row in zip(events, rows, strict=True):
        key = (row["tenant_id"], row["trace_id"], row["span_id"])
        if key in inserted_keys and key not in seen:
            seen.add(key)
            inserted.append(event)
    if inserted:
        from app.services.observability import counter_inc

        by_tenant: dict[str, int] = {}
        for event in inserted:
            metadata = _as_object((event.get("attributes") or {}).get("metadata"))
            by_tenant[metadata.get("tenant_id") or "unknown"] = by_tenant.get(metadata.get("tenant_id") or "unknown", 0) + 1
        for tenant, count in by_tenant.items():
            counter_inc("norinth_ingest_events_total", "Events accepted, by tenant", {"tenant": tenant}, count)
            counter_inc("norinth_ingest_batches_total", "Batches that inserted events, by tenant", {"tenant": tenant})
    return inserted


def event_to_row(event: dict[str, Any]) -> dict[str, Any]:
    attributes = event.get("attributes") or {}
    metadata = _as_object(attributes.get("metadata"))
    usage = _as_object(attributes.get("usage"))
    return {
        "event_type": event["type"],
        "schema_version": event["schema_version"],
        "trace_id": event["trace_id"],
        "span_id": event["span_id"],
        "parent_span_id": event.get("parent_span_id"),
        "timestamp": event["timestamp"],
        "service": event["service"],
        "environment": event["environment"],
        "project": event["project"],
        "system": event.get("system"),
        "name": event.get("name"),
        "status": event.get("status", "success"),
        "duration_ms": event.get("duration_ms"),
        "tenant_id": metadata.get("tenant_id"),
        "user_id": metadata.get("user_id"),
        "application_name": metadata.get("application_name"),
        "workflow_name": metadata.get("workflow_name"),
        "use_case": metadata.get("use_case"),
        "model_purpose": metadata.get("model_purpose"),
        "provider": attributes.get("provider"),
        "model": attributes.get("model"),
        "operation": attributes.get("operation"),
        "input_tokens": int(usage.get("input_tokens") or 0),
        "output_tokens": int(usage.get("output_tokens") or 0),
        "raw_event": serialize_raw_event(event),
    }


def count_events() -> int:
    with connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM sdk_events").fetchone()
    return int(row["count"])


def list_scopes(tenant_id: str) -> dict[str, list[str]]:
    """distinct projects/environments visible to one tenant

    tenant_id is required: project and environment names are tenant data (a
    codename like a confidential product line), so there is no unscoped listing
    """
    with connect() as connection:
        projects = connection.execute(
            "SELECT DISTINCT project FROM sdk_events WHERE tenant_id = :tenant_id ORDER BY project",
            {"tenant_id": tenant_id},
        ).fetchall()
        environments = connection.execute(
            "SELECT DISTINCT environment FROM sdk_events WHERE tenant_id = :tenant_id ORDER BY environment",
            {"tenant_id": tenant_id},
        ).fetchall()
    return {
        "tenants": [tenant_id],
        "projects": [row["project"] for row in projects],
        "environments": [row["environment"] for row in environments],
    }


def _event_filters(
    tenant_id: str | None, project: str | None, environment: str | None, event_type: str | None
) -> tuple[str, dict[str, Any]]:
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
    if event_type:
        clauses.append("event_type = :event_type")
        params["event_type"] = event_type
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def count_scoped_events(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    event_type: str | None = None,
) -> int:
    where, params = _event_filters(tenant_id, project, environment, event_type)
    with connect() as connection:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM sdk_events {where}", params).fetchone()
    return int(row["count"])


def count_events_by_type(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
) -> dict[str, int]:
    """per-event-type counts computed in sql, correct for a tenant of any size"""
    where, params = _event_filters(tenant_id, project, environment, None)
    with connect() as connection:
        rows = connection.execute(
            f"SELECT event_type, COUNT(*) AS count FROM sdk_events {where} GROUP BY event_type", params
        ).fetchall()
    return {row["event_type"]: int(row["count"]) for row in rows}


def count_error_events(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
) -> int:
    where, params = _event_filters(tenant_id, project, environment, None)
    clause = f"{where} AND status = :status" if where else "WHERE status = :status"
    params["status"] = "error"
    with connect() as connection:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM sdk_events {clause}", params).fetchone()
    return int(row["count"])


def count_distinct(
    column: str,
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
) -> int:
    # column is a fixed identifier chosen by callers, never user input
    where, params = _event_filters(tenant_id, project, environment, None)
    with connect() as connection:
        row = connection.execute(
            f"SELECT COUNT(DISTINCT {column}) AS count FROM sdk_events {where}", params
        ).fetchone()
    return int(row["count"])


def aggregate_traces(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """trace list with per-trace event counts, grouped and paged in sql

    returns (rows, total_distinct_traces) so the route never materializes every
    event to count and slice in python"""
    where, params = _event_filters(tenant_id, project, environment, None)
    with connect() as connection:
        total_row = connection.execute(
            f"SELECT COUNT(*) AS count FROM (SELECT trace_id FROM sdk_events {where} GROUP BY trace_id) AS distinct_traces",
            params,
        ).fetchone()
        page_params = {**params, "limit": limit, "offset": offset}
        rows = connection.execute(
            f"SELECT trace_id, COUNT(*) AS event_count FROM sdk_events {where} "
            "GROUP BY trace_id ORDER BY event_count DESC, trace_id LIMIT :limit OFFSET :offset",
            page_params,
        ).fetchall()
    traces = [{"trace_id": row["trace_id"], "event_count": int(row["event_count"])} for row in rows]
    return traces, int(total_row["count"])


def list_events(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    event_type: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """newest-first window of events (offset 0 = most recent), returned in
    chronological order within the window for display"""
    where, params = _event_filters(tenant_id, project, environment, event_type)
    params.update({"limit": limit, "offset": offset})
    query = f"SELECT raw_event FROM sdk_events {where} ORDER BY id DESC LIMIT :limit OFFSET :offset"
    with connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [deserialize_raw_event(row["raw_event"]) for row in reversed(rows)]

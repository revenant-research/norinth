from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import db

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "norinth.sqlite3"


def database_path() -> Path:
    return db.database_path()


def connect():
    """Open a connection to the configured backend (SQLite by default,
    PostgreSQL when NORINTH_DATABASE_URL is set). See storage/db.py."""
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
                raw_event TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_trace ON sdk_events(trace_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_tenant ON sdk_events(tenant_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_project_env ON sdk_events(project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_type ON sdk_events(event_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_application ON sdk_events(application_name)")
        # Composite index for the per-application evidence scans run on every
        # ingest (governance_policy / lifecycle recompute), audit P3.
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sdk_events_app_scope "
            "ON sdk_events(project, environment, application_name, tenant_id)"
        )
        # Idempotency: a retried batch re-sends the same (trace_id, span_id)
        # spans; a unique index plus INSERT OR IGNORE prevents double-counting
        # (audit C-6 / M4). Guarded because a legacy DB may already hold
        # duplicates from before this constraint existed.
        try:
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_sdk_events_span "
                "ON sdk_events(trace_id, span_id)"
            )
        except db.IntegrityError:
            pass


def insert_events(events: list[dict[str, Any]]) -> int:
    """Insert events idempotently and return the number newly accepted.

    Uses INSERT OR IGNORE against the unique (trace_id, span_id) index so a
    retried batch does not double-count (audit C-6). The return value is the
    count actually inserted, not the batch size.
    """
    rows = [event_to_row(event) for event in events]
    with connect() as connection:
        cursor = connection.executemany(
            """
            INSERT OR IGNORE INTO sdk_events (
                event_type, schema_version, trace_id, span_id, parent_span_id, timestamp, service,
                environment, project, system, name, status, duration_ms, tenant_id, user_id,
                application_name, workflow_name, use_case, model_purpose, provider, model,
                operation, input_tokens, output_tokens, raw_event
            )
            VALUES (
                :event_type, :schema_version, :trace_id, :span_id, :parent_span_id, :timestamp,
                :service, :environment, :project, :system, :name, :status, :duration_ms,
                :tenant_id, :user_id, :application_name, :workflow_name, :use_case,
                :model_purpose, :provider, :model, :operation, :input_tokens, :output_tokens,
                :raw_event
            )
            """,
            rows,
        )
        return max(cursor.rowcount, 0)


def event_to_row(event: dict[str, Any]) -> dict[str, Any]:
    attributes = event.get("attributes") or {}
    metadata = attributes.get("metadata") or {}
    usage = attributes.get("usage") or {}
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
        "raw_event": json.dumps(event),
    }


def count_events() -> int:
    with connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM sdk_events").fetchone()
    return int(row["count"])


def list_scopes() -> dict[str, list[str]]:
    with connect() as connection:
        tenants = connection.execute(
            "SELECT DISTINCT tenant_id FROM sdk_events WHERE tenant_id IS NOT NULL ORDER BY tenant_id"
        ).fetchall()
        projects = connection.execute("SELECT DISTINCT project FROM sdk_events ORDER BY project").fetchall()
        environments = connection.execute("SELECT DISTINCT environment FROM sdk_events ORDER BY environment").fetchall()
    return {
        "tenants": [row["tenant_id"] for row in tenants],
        "projects": [row["project"] for row in projects],
        "environments": [row["environment"] for row in environments],
    }


def list_events(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    event_type: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit}
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
    query = f"SELECT raw_event FROM sdk_events {where} ORDER BY id DESC LIMIT :limit"
    with connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [json.loads(row["raw_event"]) for row in reversed(rows)]

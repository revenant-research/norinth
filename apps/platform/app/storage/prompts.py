from __future__ import annotations

import json
from typing import Any

from .entities import entity_id
from .raw_events import connect


def init_prompts() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS prompt_templates (
                prompt_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                current_version TEXT NOT NULL,
                current_status TEXT NOT NULL,
                owner_ref TEXT,
                artifact_ref TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS prompt_versions (
                prompt_version_id TEXT PRIMARY KEY,
                prompt_id TEXT NOT NULL,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_ref TEXT,
                artifact_ref TEXT NOT NULL,
                template_summary TEXT NOT NULL,
                change_notes_summary TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                observed_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_prompt_templates_scope ON prompt_templates(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_prompt_versions_scope ON prompt_versions(tenant_id, project, environment)")


def process_prompt_events(events: list[dict[str, Any]]) -> None:
    with connect() as connection:
        for event in events:
            if event["type"] == "prompt.event":
                upsert_prompt_event(connection, event)


def upsert_prompt_event(connection, event: dict[str, Any]) -> None:
    attrs = event.get("attributes") or {}
    metadata = attrs.get("metadata") or {}
    application_name = metadata.get("application_name")
    workflow_name = metadata.get("workflow_name")
    if not application_name or not workflow_name:
        return

    prompt_id = attrs["prompt_id"]
    version = attrs["version"]
    version_id = prompt_version_key(metadata.get("tenant_id"), event["project"], event["environment"], prompt_id, version)
    template_summary = json.dumps(attrs.get("template") or {}, sort_keys=True)
    change_notes_summary = json.dumps(attrs.get("change_notes") or {}, sort_keys=True)
    status = attrs.get("prompt_status") or event.get("status", "active")
    connection.execute(
        """
        INSERT INTO prompt_templates (
            prompt_id, tenant_id, project, environment, application_name, workflow_name,
            current_version, current_status, owner_ref, artifact_ref, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(prompt_id) DO UPDATE SET
            current_version=excluded.current_version,
            current_status=excluded.current_status,
            owner_ref=excluded.owner_ref,
            artifact_ref=excluded.artifact_ref,
            last_seen=excluded.last_seen
        """,
        (
            prompt_id,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            application_name,
            workflow_name,
            version,
            status,
            attrs.get("owner_ref"),
            attrs["artifact_ref"],
            event["timestamp"],
            event["timestamp"],
        ),
    )
    connection.execute(
        """
        INSERT INTO prompt_versions (
            prompt_version_id, prompt_id, tenant_id, project, environment, application_name, workflow_name,
            version, status, owner_ref, artifact_ref, template_summary, change_notes_summary, trace_id, observed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(prompt_version_id) DO UPDATE SET
            status=excluded.status,
            owner_ref=excluded.owner_ref,
            artifact_ref=excluded.artifact_ref,
            template_summary=excluded.template_summary,
            change_notes_summary=excluded.change_notes_summary,
            trace_id=excluded.trace_id,
            observed_at=excluded.observed_at
        """,
        (
            version_id,
            prompt_id,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            application_name,
            workflow_name,
            version,
            status,
            attrs.get("owner_ref"),
            attrs["artifact_ref"],
            template_summary,
            change_notes_summary,
            event["trace_id"],
            event["timestamp"],
        ),
    )


def prompt_version_key(tenant_id: str | None, project: str, environment: str, prompt_id: str, version: str) -> str:
    return entity_id("prompt-version", tenant_id, project, environment, prompt_id, version)


def load_prompt_version(
    *,
    tenant_id: str | None,
    project: str,
    environment: str,
    application_name: str,
    workflow_name: str,
    version: str | None,
) -> dict[str, Any] | None:
    if not version:
        return None
    with connect() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM prompt_versions
            WHERE project = ?
              AND environment = ?
              AND application_name = ?
              AND workflow_name = ?
              AND version = ?
              AND ((? IS NULL AND tenant_id IS NULL) OR tenant_id = ?)
            ORDER BY observed_at DESC
            LIMIT 1
            """,
            (project, environment, application_name, workflow_name, version, tenant_id, tenant_id),
        ).fetchone()
    return None if row is None else dict(row)


def scoped_rows(table: str, *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None, order_by: str) -> list[dict[str, Any]]:
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


def list_prompt_templates(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("prompt_templates", tenant_id=tenant_id, project=project, environment=environment, order_by="last_seen")


def list_prompt_versions(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("prompt_versions", tenant_id=tenant_id, project=project, environment=environment, order_by="observed_at")

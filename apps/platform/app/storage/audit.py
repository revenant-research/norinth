from __future__ import annotations

from typing import Any

from .entities import encode_json
from .raw_events import connect


def init_audit() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor_ref TEXT NOT NULL,
                tenant_id TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                detail TEXT
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_ref)")


def record_audit(
    *,
    actor_ref: str,
    action: str,
    tenant_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append an immutable audit entry. Recording must never break the request,
    so callers may wrap this if they need defensive behavior, but the table is
    intentionally append-only with no update path."""
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO audit_logs (created_at, actor_ref, tenant_id, action, target_type, target_id, detail)
            VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)
            """,
            (
                actor_ref,
                tenant_id,
                action,
                target_type,
                target_id,
                encode_json(detail) if detail is not None else None,
            ),
        )


def list_audit_logs(
    *,
    tenant_id: str | None = None,
    actor_ref: str | None = None,
    action: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if tenant_id:
        clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if actor_ref:
        clauses.append("actor_ref = :actor_ref")
        params["actor_ref"] = actor_ref
    if action:
        clauses.append("action = :action")
        params["action"] = action
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"SELECT * FROM audit_logs {where} ORDER BY id DESC LIMIT :limit"
    with connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]

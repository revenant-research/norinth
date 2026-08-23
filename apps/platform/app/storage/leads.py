"""inbound interest from the public landing page.

pilot/demo requests are stored here and shown to platform admins in the console.
"""

from __future__ import annotations

import secrets
from typing import Any

from .raw_events import connect

INTERESTS = {"pilot", "demo", "pricing", "security"}


def ensure_leads_table(connection) -> None:
    """leads schema, idempotent"""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS leads (
            lead_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            organization TEXT NOT NULL,
            interest TEXT NOT NULL,
            message TEXT,
            source_ip TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )


def create_lead(
    *, name: str, email: str, organization: str, interest: str, message: str | None, source_ip: str | None
) -> dict[str, Any]:
    lead_id = "lead_" + secrets.token_urlsafe(9)
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO leads (lead_id, name, email, organization, interest, message, source_ip, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'new', datetime('now'), datetime('now'))
            """,
            (lead_id, name, email, organization, interest, message, source_ip),
        )
        row = connection.execute("SELECT * FROM leads WHERE lead_id = ?", (lead_id,)).fetchone()
    return dict(row)


def list_leads(*, status: str | None = None, limit: int = 200, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    where = "WHERE status = :status" if status else ""
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    with connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM leads {where} ORDER BY created_at DESC, lead_id LIMIT :limit OFFSET :offset", params
        ).fetchall()
        total = connection.execute(f"SELECT COUNT(*) AS count FROM leads {where}", params).fetchone()["count"]
    return [dict(row) for row in rows], int(total)


def set_lead_status(lead_id: str, status: str) -> dict[str, Any]:
    with connect() as connection:
        cursor = connection.execute(
            "UPDATE leads SET status = ?, updated_at = datetime('now') WHERE lead_id = ?", (status, lead_id)
        )
        if not cursor.rowcount:
            raise ValueError("lead not found")
        row = connection.execute("SELECT * FROM leads WHERE lead_id = ?", (lead_id,)).fetchone()
    return dict(row)


def count_leads_from_ip(source_ip: str, since_iso: str) -> int:
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM leads WHERE source_ip = ? AND created_at >= ?", (source_ip, since_iso)
        ).fetchone()
    return int(row["count"])

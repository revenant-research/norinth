# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from typing import Any

from .raw_events import connect


def init_organizations() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_organizations_status ON organizations(status)")


def create_organization(tenant_id: str, name: str, created_by: str) -> dict[str, Any]:
    with connect() as connection:
        existing = connection.execute(
            "SELECT 1 FROM organizations WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if existing is not None:
            raise ValueError(f"organization '{tenant_id}' already exists")
        connection.execute(
            """
            INSERT INTO organizations (tenant_id, name, status, created_by, created_at, updated_at)
            VALUES (?, ?, 'active', ?, datetime('now'), datetime('now'))
            """,
            (tenant_id, name, created_by),
        )
        return dict(connection.execute("SELECT * FROM organizations WHERE tenant_id = ?", (tenant_id,)).fetchone())


def set_organization_status(tenant_id: str, status: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT 1 FROM organizations WHERE tenant_id = ?", (tenant_id,)).fetchone()
        if row is None:
            raise ValueError("organization not found")
        connection.execute(
            "UPDATE organizations SET status = ?, updated_at = datetime('now') WHERE tenant_id = ?",
            (status, tenant_id),
        )
        return dict(connection.execute("SELECT * FROM organizations WHERE tenant_id = ?", (tenant_id,)).fetchone())


def list_organizations() -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute("SELECT * FROM organizations ORDER BY name").fetchall()
    return [dict(row) for row in rows]


def load_organization(tenant_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM organizations WHERE tenant_id = ?", (tenant_id,)).fetchone()
    return None if row is None else dict(row)


def organization_requires_mfa(tenant_id: str | None) -> bool:
    """org security policy: local-password members must hold a second factor"""
    if not tenant_id:
        return False
    with connect() as connection:
        row = connection.execute(
            "SELECT require_mfa FROM organizations WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
    return bool(row and row["require_mfa"])


def set_organization_require_mfa(tenant_id: str, require: bool) -> dict[str, Any] | None:
    with connect() as connection:
        connection.execute(
            "UPDATE organizations SET require_mfa = ? WHERE tenant_id = ?",
            (1 if require else 0, tenant_id),
        )
    return load_organization(tenant_id)


def organization_is_active(tenant_id: str | None) -> bool:
    """false when the organization is missing (purged) or suspended"""
    if not tenant_id:
        return False
    with connect() as connection:
        row = connection.execute("SELECT status FROM organizations WHERE tenant_id = ?", (tenant_id,)).fetchone()
    return row is not None and row["status"] == "active"


def organization_is_suspended(tenant_id: str | None) -> bool:
    """true only when an org row exists and is not active; a missing row (e.g
    the dev tenant) is not suspended, the ingestion key is the authority there"""
    if not tenant_id:
        return False
    with connect() as connection:
        row = connection.execute("SELECT status FROM organizations WHERE tenant_id = ?", (tenant_id,)).fetchone()
    return row is not None and row["status"] != "active"

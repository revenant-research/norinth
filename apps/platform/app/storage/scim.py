"""SCIM 2.0 provisioning tokens (per tenant).

An identity provider (Okta, Entra ID, ...) provisions and deprovisions users by
calling the SCIM endpoints with a bearer token. Each token is bound to exactly
one organization; only its SHA-256 hash is stored and the plaintext is shown
once at creation (the same model as ingestion keys).
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from .raw_events import connect

_TOKEN_PREFIX = "nrs_"


def init_scim() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scim_tokens (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_by TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT
            )
            """
        )
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_tokens_hash ON scim_tokens(token_hash)")
        # external_id lets the IdP correlate its own user id with ours.
        try:
            connection.execute("ALTER TABLE platform_users ADD COLUMN external_id TEXT")
        except Exception:
            pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _public(row: Any) -> dict[str, Any]:
    record = dict(row)
    record.pop("token_hash", None)
    return record


def create_scim_token(tenant_id: str, name: str, created_by: str | None) -> tuple[str, dict[str, Any]]:
    token = f"{_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    token_id = token[: len(_TOKEN_PREFIX) + 8]
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO scim_tokens (token_id, token_hash, tenant_id, name, status, created_by, created_at)
            VALUES (?, ?, ?, ?, 'active', ?, datetime('now'))
            """,
            (token_id, _hash(token), tenant_id, name, created_by),
        )
        row = connection.execute("SELECT * FROM scim_tokens WHERE token_id = ?", (token_id,)).fetchone()
    return token, _public(row)


def resolve_scim_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM scim_tokens WHERE token_hash = ? AND status = 'active'", (_hash(token),)
        ).fetchone()
        if row is None:
            return None
        connection.execute(
            "UPDATE scim_tokens SET last_used_at = datetime('now') WHERE token_id = ?", (row["token_id"],)
        )
        return _public(row)


def list_scim_tokens(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM scim_tokens WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
        ).fetchall()
    return [_public(row) for row in rows]


def revoke_scim_token(token_id: str, tenant_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM scim_tokens WHERE token_id = ? AND tenant_id = ?", (token_id, tenant_id)
        ).fetchone()
        if row is None:
            raise ValueError("SCIM token not found in this organization")
        connection.execute("UPDATE scim_tokens SET status = 'revoked' WHERE token_id = ?", (token_id,))
        updated = connection.execute("SELECT * FROM scim_tokens WHERE token_id = ?", (token_id,)).fetchone()
    return _public(updated)


def set_user_external_id(user_ref: str, external_id: str | None) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE platform_users SET external_id = ?, updated_at = datetime('now') WHERE user_ref = ?",
            (external_id, user_ref),
        )

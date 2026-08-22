"""Per-tenant ingestion API keys.

Replaces the previous single hard-coded ``Bearer dev`` ingestion token. Each
key is bound to exactly one tenant; the ingestion endpoint derives the tenant
from the presented key rather than trusting a client-supplied ``tenant_id`` in
the event payload. This is the root fix for cross-tenant evidence forgery
(audit finding C-1).

Keys are high-entropy random tokens. Only a SHA-256 hash of the full token is
stored; the plaintext token is shown exactly once at creation. Lookup is by
hash, so a database read never yields a usable key.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from .raw_events import connect

_TOKEN_PREFIX = "nrk_"


def init_ingestion_keys() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ingestion_keys (
                key_id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_by TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT
            )
            """
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ingestion_keys_hash ON ingestion_keys(key_hash)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_ingestion_keys_tenant ON ingestion_keys(tenant_id)"
        )


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _public_key_id(token: str) -> str:
    # A short, non-secret identifier derived from the token prefix for display
    # and revocation. Never enough to reconstruct the token.
    return token[: len(_TOKEN_PREFIX) + 8]


def _row_to_public(row: Any) -> dict[str, Any]:
    record = dict(row)
    record.pop("key_hash", None)
    return record


def create_ingestion_key(tenant_id: str, name: str, created_by: str | None) -> tuple[str, dict[str, Any]]:
    """Create a key for ``tenant_id`` and return ``(plaintext_token, public_record)``.

    The plaintext token is returned only here and never stored.
    """
    token = f"{_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    key_id = _public_key_id(token)
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO ingestion_keys (key_id, key_hash, tenant_id, name, status, created_by, created_at)
            VALUES (?, ?, ?, ?, 'active', ?, datetime('now'))
            """,
            (key_id, hash_token(token), tenant_id, name, created_by),
        )
        row = connection.execute("SELECT * FROM ingestion_keys WHERE key_id = ?", (key_id,)).fetchone()
    return token, _row_to_public(row)


def seed_dev_ingestion_key(tenant_id: str, token: str = "dev") -> None:
    """Seed a well-known development key so the local quickstart keeps working.

    Only used in development (see services.bootstrap). The key is still bound to
    a single tenant, so even the dev token cannot forge evidence for another
    tenant.
    """
    with connect() as connection:
        existing = connection.execute(
            "SELECT 1 FROM ingestion_keys WHERE key_hash = ?", (hash_token(token),)
        ).fetchone()
        if existing is not None:
            return
        connection.execute(
            """
            INSERT INTO ingestion_keys (key_id, key_hash, tenant_id, name, status, created_by, created_at)
            VALUES (?, ?, ?, 'development default', 'active', 'bootstrap', datetime('now'))
            """,
            (f"{_TOKEN_PREFIX}dev", hash_token(token), tenant_id),
        )


def resolve_ingestion_key(token: str | None) -> dict[str, Any] | None:
    """Return the active key record for ``token``, or ``None`` if invalid.

    Updates ``last_used_at`` on success.
    """
    if not token:
        return None
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM ingestion_keys WHERE key_hash = ? AND status = 'active'",
            (hash_token(token),),
        ).fetchone()
        if row is None:
            return None
        connection.execute(
            "UPDATE ingestion_keys SET last_used_at = datetime('now') WHERE key_id = ?",
            (row["key_id"],),
        )
        return _row_to_public(row)


def list_ingestion_keys(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM ingestion_keys WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    return [_row_to_public(row) for row in rows]


def revoke_ingestion_key(key_id: str, tenant_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM ingestion_keys WHERE key_id = ? AND tenant_id = ?",
            (key_id, tenant_id),
        ).fetchone()
        if row is None:
            raise ValueError("ingestion key not found in this organization")
        connection.execute(
            "UPDATE ingestion_keys SET status = 'revoked' WHERE key_id = ?",
            (key_id,),
        )
        updated = connection.execute("SELECT * FROM ingestion_keys WHERE key_id = ?", (key_id,)).fetchone()
    return _row_to_public(updated)

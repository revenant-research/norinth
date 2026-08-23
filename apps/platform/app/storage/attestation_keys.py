"""Per-tenant evidence attestation keys.

A deployment gate is only as trustworthy as the eval evidence behind it. An
``eval.result`` event is client-authored: whoever holds an ingestion key can
send ``passed: true``. Attestation binds passing evals to a *CI identity*: the
organization registers the public half of an Ed25519 key that its CI pipeline
uses to sign eval results, and the platform verifies the signature at
ingestion. Once an organization has an active attestation key, unattested
evals no longer satisfy its deployment gates.

Only public keys are stored; the private key never leaves the CI system.
"""

from __future__ import annotations

import secrets
from typing import Any

from .raw_events import connect


def ensure_attestation_tables(connection) -> None:
    """Schema for migration 5 (idempotent)."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS attestation_keys (
            key_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'ed25519',
            public_key_pem TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_by TEXT,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            last_used_at TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_attestation_keys_tenant_status ON attestation_keys (tenant_id, status)"
    )


def create_attestation_key(
    tenant_id: str, name: str, public_key_pem: str, created_by: str | None
) -> dict[str, Any]:
    key_id = "nak_" + secrets.token_urlsafe(9)
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO attestation_keys (key_id, tenant_id, name, algorithm, public_key_pem, status, created_by, created_at)
            VALUES (?, ?, ?, 'ed25519', ?, 'active', ?, datetime('now'))
            """,
            (key_id, tenant_id, name, public_key_pem, created_by),
        )
        row = connection.execute("SELECT * FROM attestation_keys WHERE key_id = ?", (key_id,)).fetchone()
    return _public(dict(row))


def list_attestation_keys(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM attestation_keys WHERE tenant_id = ? ORDER BY created_at DESC, key_id",
            (tenant_id,),
        ).fetchall()
    return [_public(dict(row)) for row in rows]


def load_active_attestation_key(tenant_id: str, key_id: str) -> dict[str, Any] | None:
    """Tenant-bound lookup: a key registered by another organization can never
    verify this organization's evidence."""
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM attestation_keys WHERE key_id = ? AND tenant_id = ? AND status = 'active'",
            (key_id, tenant_id),
        ).fetchone()
    return None if row is None else dict(row)


def tenant_requires_attestation(tenant_id: str | None, connection=None) -> bool:
    """Registering a key is the opt-in: from then on only attested evals count.
    Accepts an open connection so gate recomputation stays in one transaction."""
    if not tenant_id:
        return False
    query = "SELECT COUNT(*) AS count FROM attestation_keys WHERE tenant_id = ? AND status = 'active'"
    if connection is not None:
        row = connection.execute(query, (tenant_id,)).fetchone()
    else:
        with connect() as owned:
            row = owned.execute(query, (tenant_id,)).fetchone()
    return int(row["count"]) > 0


def revoke_attestation_key(key_id: str, tenant_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM attestation_keys WHERE key_id = ? AND tenant_id = ?", (key_id, tenant_id)
        ).fetchone()
        if row is None:
            raise ValueError("attestation key not found")
        connection.execute(
            "UPDATE attestation_keys SET status = 'revoked', revoked_at = datetime('now') WHERE key_id = ? AND tenant_id = ?",
            (key_id, tenant_id),
        )
        row = connection.execute("SELECT * FROM attestation_keys WHERE key_id = ?", (key_id,)).fetchone()
    return _public(dict(row))


def touch_attestation_key(key_id: str) -> None:
    with connect() as connection:
        connection.execute("UPDATE attestation_keys SET last_used_at = datetime('now') WHERE key_id = ?", (key_id,))


def _public(row: dict[str, Any]) -> dict[str, Any]:
    # The public key is not secret, but it is long; expose a fingerprint for
    # listing and keep the PEM available for verification tooling.
    from app.services.attestation import public_key_fingerprint

    return {**row, "fingerprint": public_key_fingerprint(row["public_key_pem"])}

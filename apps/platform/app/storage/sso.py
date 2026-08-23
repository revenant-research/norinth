"""Per-tenant OpenID Connect (SSO) configuration and login-flow state.

Enterprise buyers require SSO (SAML/OIDC) as table-stakes; password-only
authentication blocks procurement. This module stores each organization's OIDC
provider settings and the short-lived state for in-flight authorization-code
logins (state + nonce + PKCE verifier), which protects the flow against CSRF,
replay, and code interception.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from app.services.secrets import decrypt, encrypt

from .raw_events import connect

STATE_TTL_MINUTES = 10


def init_sso() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sso_configurations (
                tenant_id TEXT PRIMARY KEY,
                issuer TEXT NOT NULL,
                client_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                authorization_endpoint TEXT NOT NULL,
                token_endpoint TEXT NOT NULL,
                jwks_uri TEXT NOT NULL,
                default_role TEXT NOT NULL DEFAULT 'governance_viewer',
                allowed_email_domain TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sso_login_states (
                state TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                code_verifier TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )


def upsert_sso_configuration(
    *,
    tenant_id: str,
    issuer: str,
    client_id: str,
    client_secret: str,
    authorization_endpoint: str,
    token_endpoint: str,
    jwks_uri: str,
    default_role: str,
    allowed_email_domain: str | None,
    created_by: str | None,
) -> dict[str, Any]:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO sso_configurations (
                tenant_id, issuer, client_id, client_secret, authorization_endpoint, token_endpoint,
                jwks_uri, default_role, allowed_email_domain, enabled, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id) DO UPDATE SET
                issuer=excluded.issuer,
                client_id=excluded.client_id,
                client_secret=excluded.client_secret,
                authorization_endpoint=excluded.authorization_endpoint,
                token_endpoint=excluded.token_endpoint,
                jwks_uri=excluded.jwks_uri,
                default_role=excluded.default_role,
                allowed_email_domain=excluded.allowed_email_domain,
                enabled=1,
                updated_at=datetime('now')
            """,
            (
                tenant_id,
                issuer,
                client_id,
                # Encrypted at rest, bound to the tenant so a row cannot be
                # transplanted to another organization.
                encrypt(client_secret, associated_data=tenant_id),
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
                default_role,
                allowed_email_domain,
                created_by,
            ),
        )
        return public_sso_configuration(load_sso_configuration(tenant_id, connection))


def _decrypted(row: Any, tenant_id: str) -> dict[str, Any] | None:
    if row is None:
        return None
    record = dict(row)
    record["client_secret"] = decrypt(record["client_secret"], associated_data=tenant_id)
    return record


def load_sso_configuration(tenant_id: str, connection=None) -> dict[str, Any] | None:
    if connection is not None:
        row = connection.execute("SELECT * FROM sso_configurations WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return _decrypted(row, tenant_id)
    with connect() as conn:
        row = conn.execute("SELECT * FROM sso_configurations WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return _decrypted(row, tenant_id)


def public_sso_configuration(config: dict[str, Any] | None) -> dict[str, Any] | None:
    """Strip the client secret for API responses."""
    if config is None:
        return None
    return {key: value for key, value in config.items() if key != "client_secret"}


def disable_sso_configuration(tenant_id: str) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE sso_configurations SET enabled = 0, updated_at = datetime('now') WHERE tenant_id = ?",
            (tenant_id,),
        )


def create_login_state(tenant_id: str) -> dict[str, str]:
    """Create and persist state/nonce/PKCE for one authorization-code login."""
    now = datetime.now(UTC)
    record = {
        "state": secrets.token_urlsafe(32),
        "tenant_id": tenant_id,
        "nonce": secrets.token_urlsafe(24),
        "code_verifier": secrets.token_urlsafe(64),
    }
    with connect() as connection:
        connection.execute(
            "DELETE FROM sso_login_states WHERE expires_at <= ?", (now.isoformat(),)
        )
        connection.execute(
            """
            INSERT INTO sso_login_states (state, tenant_id, nonce, code_verifier, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record["state"],
                tenant_id,
                record["nonce"],
                record["code_verifier"],
                now.isoformat(),
                (now + timedelta(minutes=STATE_TTL_MINUTES)).isoformat(),
            ),
        )
    return record


def consume_login_state(state: str) -> dict[str, Any] | None:
    """Fetch and delete a login state (single use). Returns None if unknown or expired."""
    now = datetime.now(UTC).isoformat()
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM sso_login_states WHERE state = ? AND expires_at > ?", (state, now)
        ).fetchone()
        connection.execute("DELETE FROM sso_login_states WHERE state = ?", (state,))
        return None if row is None else dict(row)

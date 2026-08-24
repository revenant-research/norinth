"""per-tenant saml 2.0 configuration and in-flight request state

the platform is the service provider; the idp's signing certificate is stored
so assertions can be verified
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from .raw_events import connect

REQUEST_TTL_MINUTES = 10


def ensure_saml_tables(connection) -> None:
    """saml tables schema, idempotent"""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS saml_configurations (
            tenant_id TEXT PRIMARY KEY,
            idp_entity_id TEXT NOT NULL,
            idp_sso_url TEXT NOT NULL,
            idp_certificate TEXT NOT NULL,
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
        CREATE TABLE IF NOT EXISTS saml_requests (
            request_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )


def upsert_saml_configuration(
    *,
    tenant_id: str,
    idp_entity_id: str,
    idp_sso_url: str,
    idp_certificate: str,
    default_role: str,
    allowed_email_domain: str | None,
    created_by: str | None,
) -> dict[str, Any]:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO saml_configurations (
                tenant_id, idp_entity_id, idp_sso_url, idp_certificate, default_role,
                allowed_email_domain, enabled, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id) DO UPDATE SET
                idp_entity_id=excluded.idp_entity_id,
                idp_sso_url=excluded.idp_sso_url,
                idp_certificate=excluded.idp_certificate,
                default_role=excluded.default_role,
                allowed_email_domain=excluded.allowed_email_domain,
                enabled=1,
                updated_at=datetime('now')
            """,
            (tenant_id, idp_entity_id, idp_sso_url, idp_certificate, default_role, allowed_email_domain, created_by),
        )
        row = connection.execute("SELECT * FROM saml_configurations WHERE tenant_id = ?", (tenant_id,)).fetchone()
    return dict(row)


def load_saml_configuration(tenant_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM saml_configurations WHERE tenant_id = ?", (tenant_id,)).fetchone()
    return None if row is None else dict(row)


def disable_saml_configuration(tenant_id: str) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE saml_configurations SET enabled = 0, updated_at = datetime('now') WHERE tenant_id = ?",
            (tenant_id,),
        )


def create_saml_request(tenant_id: str) -> str:
    """persist an authnrequest id so the response's inresponseto can be checked;
    prevents unsolicited/replayed responses, single use"""
    now = datetime.now(UTC)
    request_id = "_" + secrets.token_hex(20)  # saml ids must be valid xs:ID, not start with a digit
    with connect() as connection:
        connection.execute("DELETE FROM saml_requests WHERE expires_at <= ?", (now.isoformat(),))
        connection.execute(
            "INSERT INTO saml_requests (request_id, tenant_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (request_id, tenant_id, now.isoformat(), (now + timedelta(minutes=REQUEST_TTL_MINUTES)).isoformat()),
        )
    return request_id


def consume_saml_request(request_id: str) -> dict[str, Any] | None:
    now = datetime.now(UTC).isoformat()
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM saml_requests WHERE request_id = ? AND expires_at > ?", (request_id, now)
        ).fetchone()
        connection.execute("DELETE FROM saml_requests WHERE request_id = ?", (request_id,))
        return None if row is None else dict(row)

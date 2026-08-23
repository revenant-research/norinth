"""Versioned schema migrations.

Replaces "run every CREATE/ALTER on every boot and swallow the errors" (audit
M1) with an ordered, recorded migration history:

* ``schema_migrations`` records every applied version with a timestamp.
* Each migration runs once, in its own transaction, in version order.
* Migration 0001 is the baseline: it calls the storage modules' idempotent
  ``init_*`` functions (CREATE TABLE IF NOT EXISTS ...). Existing databases
  and fresh ones converge on the same schema, and the version is recorded.
* Every schema change from here on is a new numbered migration below, so an
  operator can see exactly what a deployment will change (``norinth-migrate``
  or ``GET /api/admin/schema``) and the same migration runs identically on
  SQLite and PostgreSQL.

Keep migrations additive and backward-compatible with the running code
(expand/contract): add columns/tables in one release, remove in a later one.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import db
from .raw_events import connect


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Any], None]  # receives a connection inside a transaction


# --- migrations -----------------------------------------------------------------


def _baseline(connection) -> None:
    """Baseline schema: every storage module's idempotent initializer.

    Runs outside the passed connection because the init functions open their
    own; they are all CREATE IF NOT EXISTS / guarded ALTERs, so this is safe on
    both fresh and pre-existing databases.
    """
    from app.storage.agents import init_agents
    from app.storage.audit import init_audit
    from app.storage.deployments import init_deployments
    from app.storage.entities import init_entities
    from app.storage.governance_policy import init_governance_policy
    from app.storage.incidents import init_incidents
    from app.storage.ingestion_keys import init_ingestion_keys
    from app.storage.intake import init_intake
    from app.storage.lifecycle import init_lifecycle
    from app.storage.login_attempts import init_login_attempts
    from app.storage.organizations import init_organizations
    from app.storage.prompts import init_prompts
    from app.storage.raw_events import init_storage
    from app.storage.scim import init_scim
    from app.storage.sso import init_sso
    from app.storage.workflow import init_workflow

    for initializer in (
        init_storage,
        init_entities,
        init_governance_policy,
        init_lifecycle,
        init_workflow,
        init_deployments,
        init_incidents,
        init_prompts,
        init_organizations,
        init_intake,
        init_audit,
        init_ingestion_keys,
        init_login_attempts,
        init_sso,
        init_scim,
        init_agents,
    ):
        initializer()


def _0002_event_ingest_indexes(connection) -> None:
    """Indexes for the agent-posture and audit queries added in 2026-08."""
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_observed_events_type_tenant "
        "ON governance_observed_events(entity_type, tenant_id)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_risk_findings_rule ON risk_findings(rule_id)")


def _0003_saml(connection) -> None:
    """SAML 2.0 SSO: per-tenant IdP configuration and in-flight request ids."""
    from app.storage.saml import ensure_saml_tables

    ensure_saml_tables(connection)


def _0004_login_throttle(connection) -> None:
    """Per-IP + per-account login throttling table (replaces login_attempts)."""
    from app.storage.login_attempts import ensure_login_throttle_table

    ensure_login_throttle_table(connection)
    connection.execute("DROP TABLE IF EXISTS login_attempts")


def _0005_attestation_keys(connection) -> None:
    """Per-tenant Ed25519 public keys for signed eval evidence."""
    from app.storage.attestation_keys import ensure_attestation_tables

    ensure_attestation_tables(connection)


def _0006_leads(connection) -> None:
    """Inbound pilot/demo requests captured by the public landing page."""
    from app.storage.leads import ensure_leads_table

    ensure_leads_table(connection)


def _0007_notifications(connection) -> None:
    """Notification outbox, webhooks, invites."""
    from app.storage.notifications import ensure_notification_tables

    ensure_notification_tables(connection)


def _0008_outbox_claims(connection) -> None:
    """Delivery claim columns so multiple replicas never deliver the same row."""
    from app.storage.notifications import ensure_claim_columns

    ensure_claim_columns(connection)


def _0010_cross_tenant_keys(connection) -> None:
    """Make record identity tenant-scoped so one tenant's ingestion key cannot
    overwrite another's records. governance_deployments, governance_incidents
    and prompt_templates move from a client-id primary key to a composite
    (tenant_id, project, environment, id); the sdk_events dedup index gains
    tenant_id. Existing rows keep their data (tenant '' where it was NULL)."""
    rebuilds = {
        "governance_deployments": (
            "deployment_id TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '', project TEXT NOT NULL, "
            "environment TEXT NOT NULL, application_name TEXT NOT NULL, workflow_name TEXT NOT NULL, "
            "current_version TEXT NOT NULL, current_status TEXT NOT NULL, provider TEXT, model TEXT, "
            "artifact_ref TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
            "PRIMARY KEY (tenant_id, project, environment, deployment_id)",
            "deployment_id, project, environment, application_name, workflow_name, current_version, "
            "current_status, provider, model, artifact_ref, first_seen, last_seen",
        ),
        "prompt_templates": (
            "prompt_id TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '', project TEXT NOT NULL, "
            "environment TEXT NOT NULL, application_name TEXT NOT NULL, workflow_name TEXT NOT NULL, "
            "current_version TEXT NOT NULL, current_status TEXT NOT NULL, owner_ref TEXT, "
            "artifact_ref TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
            "PRIMARY KEY (tenant_id, project, environment, prompt_id)",
            "prompt_id, project, environment, application_name, workflow_name, current_version, "
            "current_status, owner_ref, artifact_ref, first_seen, last_seen",
        ),
        "governance_incidents": (
            "incident_id TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '', project TEXT NOT NULL, "
            "environment TEXT NOT NULL, application_name TEXT NOT NULL, workflow_name TEXT NOT NULL, "
            "title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, description_summary TEXT NOT NULL, "
            "detected_by TEXT, trace_id TEXT NOT NULL, impacted_trace_id TEXT, provider TEXT, model TEXT, "
            "risk_count INTEGER NOT NULL, missing_control_count INTEGER NOT NULL, deployment_id TEXT, "
            "deployment_version_id TEXT, deployment_gate_id TEXT, actor_ref TEXT, resolution_rationale TEXT, "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, closed_at TEXT, "
            "PRIMARY KEY (tenant_id, project, environment, incident_id)",
            "incident_id, project, environment, application_name, workflow_name, title, severity, status, "
            "description_summary, detected_by, trace_id, impacted_trace_id, provider, model, risk_count, "
            "missing_control_count, deployment_id, deployment_version_id, deployment_gate_id, actor_ref, "
            "resolution_rationale, first_seen, last_seen, closed_at",
        ),
    }
    for table, (schema, columns) in rebuilds.items():
        connection.execute(f"ALTER TABLE {table} RENAME TO {table}_old10")
        connection.execute(f"CREATE TABLE {table} ({schema})")
        connection.execute(
            f"INSERT INTO {table} (tenant_id, {columns}) SELECT COALESCE(tenant_id, ''), {columns} FROM {table}_old10"
        )
        connection.execute(f"DROP TABLE {table}_old10")
    # Rebuild the events dedup index to include tenant.
    connection.execute("DROP INDEX IF EXISTS idx_sdk_events_span")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sdk_events_span_tenant ON sdk_events(tenant_id, trace_id, span_id)")


def _0011_audit_hmac(connection) -> None:
    """Add the audit-chain HMAC column (keyed by NORINTH_SECRET_KEY)."""
    try:
        connection.execute("ALTER TABLE audit_logs ADD COLUMN row_hmac TEXT")
    except Exception:  # noqa: BLE001 - column already exists
        pass


MIGRATIONS: list[Migration] = [
    Migration(1, "baseline schema", _baseline),
    Migration(2, "indexes for agent posture, audit actions, risk rules", _0002_event_ingest_indexes),
    Migration(3, "SAML 2.0 configuration and request state", _0003_saml),
    Migration(4, "per-IP login throttling", _0004_login_throttle),
    Migration(5, "evidence attestation keys", _0005_attestation_keys),
    Migration(6, "inbound leads from the landing page", _0006_leads),
    Migration(7, "notification outbox, webhooks, invites", _0007_notifications),
    Migration(8, "outbox delivery claims for multi-replica workers", _0008_outbox_claims),
]


# --- runner -----------------------------------------------------------------------


def _ensure_table() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )


def applied_versions() -> list[dict[str, Any]]:
    _ensure_table()
    with connect() as connection:
        rows = connection.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall()
    return [dict(row) for row in rows]


def pending_migrations() -> list[Migration]:
    done = {row["version"] for row in applied_versions()}
    return [migration for migration in MIGRATIONS if migration.version not in done]


def run_migrations() -> list[int]:
    """Apply all pending migrations in order. Returns the versions applied."""
    applied: list[int] = []
    for migration in pending_migrations():
        if migration.version == 1:
            # The baseline initializers manage their own connections.
            migration.apply(None)
            with connect() as connection:
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))",
                    (migration.version, migration.name),
                )
        else:
            with connect() as connection:
                migration.apply(connection)
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))",
                    (migration.version, migration.name),
                )
        applied.append(migration.version)
    return applied


def schema_status() -> dict[str, Any]:
    return {
        "backend": "postgresql" if db.is_postgres() else "sqlite",
        "current_version": max((m.version for m in MIGRATIONS), default=0),
        "applied": applied_versions(),
        "pending": [{"version": m.version, "name": m.name} for m in pending_migrations()],
    }


def main() -> None:  # pragma: no cover - CLI entry
    import json

    applied = run_migrations()
    print(json.dumps({"applied_now": applied, **schema_status()}, indent=2, default=str))


if __name__ == "__main__":  # pragma: no cover
    main()

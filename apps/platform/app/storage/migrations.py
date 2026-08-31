# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""versioned schema migrations

* schema_migrations records every applied version with a timestamp
* each migration runs once, in its own transaction, in version order
* migration 1 is the baseline: it calls the storage modules' idempotent init_*
  functions, so fresh and existing databases converge on the same schema
* every schema change after that is a new numbered migration below, running
  identically on sqlite and postgres

keep migrations additive and backward-compatible (expand/contract): add
columns/tables in one release, remove in a later one
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from . import db
from .raw_events import connect

# session-scoped advisory lock so only one replica migrates at a time; without
# it, two replicas booting against an empty postgres both CREATE TABLE and one
# crashes on a duplicate-object error. sqlite is single-process, so it's a no-op
_MIGRATION_LOCK_KEY = 4242000042420002


@contextlib.contextmanager
def _migration_lock() -> Iterator[None]:
    if not db.is_postgres():
        yield
        return
    lock_conn = connect()
    try:
        lock_conn.execute(f"SELECT pg_advisory_lock({_MIGRATION_LOCK_KEY})")
        yield
    finally:
        try:
            lock_conn.execute(f"SELECT pg_advisory_unlock({_MIGRATION_LOCK_KEY})")
        finally:
            lock_conn.close()


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Any], None]  # receives a connection inside a transaction


# --- migrations -----------------------------------------------------------------


def _baseline(connection) -> None:
    """baseline schema: every storage module's idempotent initializer

    runs outside the passed connection since the init functions open their own;
    all CREATE IF NOT EXISTS / guarded ALTERs, safe on fresh and existing dbs

    warning: the baseline is recorded once per db, so editing an init_* to add a
    column or table won't reach dbs that already recorded migration 1 - it would
    apply only to fresh installs. every schema change after the baseline must be
    a new Migration(...) appended to MIGRATIONS, never an edit to an init_*
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
    """indexes for the agent-posture and audit queries"""
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_observed_events_type_tenant "
        "ON governance_observed_events(entity_type, tenant_id)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_risk_findings_rule ON risk_findings(rule_id)")


def _0003_saml(connection) -> None:
    """SAML 2.0 SSO: per-tenant IdP configuration and in-flight request ids"""
    from app.storage.saml import ensure_saml_tables

    ensure_saml_tables(connection)


def _0004_login_throttle(connection) -> None:
    """per-ip + per-account login throttling table"""
    from app.storage.login_attempts import ensure_login_throttle_table

    ensure_login_throttle_table(connection)
    connection.execute("DROP TABLE IF EXISTS login_attempts")


def _0005_attestation_keys(connection) -> None:
    """Per-tenant Ed25519 public keys for signed eval evidence"""
    from app.storage.attestation_keys import ensure_attestation_tables

    ensure_attestation_tables(connection)


def _0006_leads(connection) -> None:
    """no-op

    this once created a leads table for a public landing-page contact form;
    that commercial lead-capture flow was removed (norinth self-hosts, there
    is no vendor inbox). migration 13 drops the table on installs that have it
    """


def _0007_notifications(connection) -> None:
    """Notification outbox, webhooks, invites"""
    from app.storage.notifications import ensure_notification_tables

    ensure_notification_tables(connection)


def _0008_outbox_claims(connection) -> None:
    """Delivery claim columns so multiple replicas never deliver the same row"""
    from app.storage.notifications import ensure_claim_columns

    ensure_claim_columns(connection)


def _0009_config_table_tenancy(connection) -> None:
    """add tenant_id to the config tables and rebuild with a composite primary
    key; existing rows become platform defaults (tenant_id '')"""
    rebuilds = {
        "control_library": (
            "tenant_id TEXT NOT NULL DEFAULT '', control_id TEXT NOT NULL, name TEXT NOT NULL, "
            "framework_refs TEXT NOT NULL, evidence_event_types TEXT NOT NULL, required_fields TEXT NOT NULL, "
            "rationale TEXT NOT NULL, PRIMARY KEY (tenant_id, control_id)",
            "control_id, name, framework_refs, evidence_event_types, required_fields, rationale",
        ),
        "risk_rules": (
            "tenant_id TEXT NOT NULL DEFAULT '', rule_id TEXT NOT NULL, name TEXT NOT NULL, signal TEXT NOT NULL, "
            "severity TEXT NOT NULL, framework_refs TEXT NOT NULL, rationale TEXT NOT NULL, "
            "PRIMARY KEY (tenant_id, rule_id)",
            "rule_id, name, signal, severity, framework_refs, rationale",
        ),
        "review_queue_policies": (
            "tenant_id TEXT NOT NULL DEFAULT '', policy_id TEXT NOT NULL, task_type TEXT NOT NULL, "
            "assigned_role TEXT NOT NULL, due_days INTEGER NOT NULL, escalation_days INTEGER NOT NULL, "
            "source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, policy_id)",
            "policy_id, task_type, assigned_role, due_days, escalation_days, source, created_at, updated_at",
        ),
        "owner_assignment_policies": (
            "tenant_id TEXT NOT NULL DEFAULT '', policy_id TEXT NOT NULL, subject_type TEXT NOT NULL, "
            "owner_role TEXT NOT NULL, applies_to_status TEXT, source TEXT NOT NULL, created_at TEXT NOT NULL, "
            "updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, policy_id)",
            "policy_id, subject_type, owner_role, applies_to_status, source, created_at, updated_at",
        ),
    }
    for table, (schema, columns) in rebuilds.items():
        existing = connection.execute(f"SELECT * FROM {table} LIMIT 1").fetchone()
        if existing is not None and "tenant_id" in dict(existing):
            continue  # already migrated
        connection.execute(f"ALTER TABLE {table} RENAME TO {table}_old")
        connection.execute(f"CREATE TABLE {table} ({schema})")
        connection.execute(f"INSERT INTO {table} (tenant_id, {columns}) SELECT '', {columns} FROM {table}_old")
        connection.execute(f"DROP TABLE {table}_old")


def _0010_cross_tenant_keys(connection) -> None:
    """make record identity tenant-scoped so one tenant's key can't overwrite
    another's records: deployments, incidents and prompt_templates move to a
    composite (tenant_id, project, environment, id) key and the sdk_events dedup
    index gains tenant_id"""
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
    # rebuild the events dedup index to include tenant
    connection.execute("DROP INDEX IF EXISTS idx_sdk_events_span")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sdk_events_span_tenant ON sdk_events(tenant_id, trace_id, span_id)")


def _0011_audit_hmac(connection) -> None:
    """add the audit-chain hmac column (keyed by NORINTH_SECRET_KEY)"""
    try:
        connection.execute("ALTER TABLE audit_logs ADD COLUMN row_hmac TEXT")
    except Exception:  # noqa: BLE001 - column already exists
        pass


def _has_column(connection, table: str, column: str) -> bool:
    from app.storage.db import is_postgres

    if is_postgres():
        rows = connection.execute(
            f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}'"
        ).fetchall()
        return any(row["column_name"] == column for row in rows)
    rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def _0012_drop_risk_confidence(connection) -> None:
    """drop the per-rule confidence score from the risk tables

    risk detections are deterministic (a signal condition is met or it isn't),
    so a fixed 0-1 confidence was never computed from anything; it was a constant
    riding into the api and audit exports as if it were evidence. remove it
    """
    for table in ("risk_findings", "risk_rules", "governance_risks"):
        if _has_column(connection, table, "confidence"):
            connection.execute(f"ALTER TABLE {table} DROP COLUMN confidence")


def _0013_drop_leads(connection) -> None:
    """drop the leads table left by the removed landing-page lead-capture flow"""
    connection.execute("DROP TABLE IF EXISTS leads")


def _0015_audit_hash_version(connection) -> None:
    """record the audit hash algorithm per row so the chain can evolve

    existing rows were written by the current algorithm, so default 1; a later
    algorithm is a new version and leaves these verifiable under version 1
    """
    if not _has_column(connection, "audit_logs", "hash_version"):
        connection.execute("ALTER TABLE audit_logs ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1")


def _0014_org_retention_window(connection) -> None:
    """per-organization telemetry retention window

    null means keep everything, so an existing install never starts deleting
    because it upgraded; a window only applies once the organization sets one
    """
    if not _has_column(connection, "organizations", "retention_days"):
        connection.execute("ALTER TABLE organizations ADD COLUMN retention_days INTEGER")


def _0016_event_ingested_at(connection) -> None:
    """server-stamped ingest time on raw events

    retention compared only the client-supplied event timestamp, so a client that
    future-dates its events could keep them past the window forever. record when
    the platform actually ingested each event; retention now also ages out on
    this. existing rows are backfilled to their event timestamp, the only signal
    available for already-stored rows
    """
    if not _has_column(connection, "sdk_events", "ingested_at"):
        connection.execute("ALTER TABLE sdk_events ADD COLUMN ingested_at TEXT")
        connection.execute("UPDATE sdk_events SET ingested_at = timestamp WHERE ingested_at IS NULL")


def _0017_audit_hmac_key_id(connection) -> None:
    """record which hmac key anchored each audit row

    lets the audit hmac key rotate without previously written rows reading as
    tampered: verification checks each row under the key named here. rows written
    before this migration carried an hmac under the single legacy key, so backfill
    them to 'legacy'
    """
    if not _has_column(connection, "audit_logs", "hmac_key_id"):
        connection.execute("ALTER TABLE audit_logs ADD COLUMN hmac_key_id TEXT")
        connection.execute("UPDATE audit_logs SET hmac_key_id = 'legacy' WHERE row_hmac IS NOT NULL AND hmac_key_id IS NULL")


def _0019_mfa(connection) -> None:
    """totp multi-factor authentication

    per-user secret (encrypted at rest via services/secrets), single-use
    recovery codes (hashed), and short-lived login challenges so the password
    step never issues a session on an mfa-enrolled account. last_counter makes
    each totp code single-use
    """
    for statement in (
        "ALTER TABLE platform_users ADD COLUMN mfa_secret TEXT",
        "ALTER TABLE platform_users ADD COLUMN mfa_pending_secret TEXT",
        "ALTER TABLE platform_users ADD COLUMN mfa_enabled_at TEXT",
        "ALTER TABLE platform_users ADD COLUMN mfa_last_counter INTEGER",
    ):
        column = statement.split(" ADD COLUMN ")[1].split(" ")[0]
        if not _has_column(connection, "platform_users", column):
            connection.execute(statement)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            user_ref TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT,
            PRIMARY KEY (user_ref, code_hash)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_challenges (
            token TEXT PRIMARY KEY,
            user_ref TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
def _0018_session_last_seen(connection) -> None:
    """activity timestamp on sessions for the idle timeout

    an absolute ttl alone leaves a session usable for hours on an abandoned
    workstation. rows from before this migration have no activity signal, so
    they stay NULL and the resolver falls back to created_at — a legacy idle
    session ages out instead of being grandfathered in
    """
    if not _has_column(connection, "sessions", "last_seen_at"):
        connection.execute("ALTER TABLE sessions ADD COLUMN last_seen_at TEXT")


def _0020_org_require_mfa(connection) -> None:
    """org security policy: require a second factor on local-password accounts

    off by default so an upgrade never locks an organization's members out of
    anything; when an org admin turns it on, unenrolled members keep their
    password login but can reach only the enrollment endpoints until a second
    factor is active. sso/scim accounts (no local password) are exempt — their
    factor lives at the idp
    """
    if not _has_column(connection, "organizations", "require_mfa"):
        connection.execute("ALTER TABLE organizations ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0")


def _0021_detail_view_indexes(connection) -> None:
    """indexes for the detail views now that they filter in sql

    application and trace lookups already had one; workflow did not, and the
    system rollup groups on COALESCE(system, service)
    """
    # tenant first, then the narrowing column. the existing app index leads with
    # project and environment, which a tenant-only scope leaves unconstrained, so
    # the planner could not use it and fell back to a scan
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sdk_events_tenant_application "
        "ON sdk_events(tenant_id, application_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sdk_events_tenant_workflow "
        "ON sdk_events(tenant_id, workflow_name)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sdk_events_name ON sdk_events(name)")


def _0022_governance_policy_engine(connection) -> None:
    """governance policy engine: versioned policy documents, approval stages,
    vendor registry, gate policy pins, and custom intake fields

    seeds the platform default policy (tenant_id '', version 1, active), which
    encodes pre-policy behavior exactly; an install that never authors a policy
    behaves as it did before this migration
    """
    from app.storage.entities import encode_json
    from app.storage.policy_engine import (
        VENDOR_RISK_RULES,
        ensure_policy_engine_tables,
        seed_default_policy,
    )
    from app.storage.workflow import seed_review_queue_policies

    ensure_policy_engine_tables(connection)
    seed_default_policy(connection)
    # gate snapshots record the policy version consulted; intake stores the
    # policy-declared custom fields
    for table, statement in (
        ("deployment_approval_gates", "ALTER TABLE deployment_approval_gates ADD COLUMN policy_tenant TEXT"),
        ("deployment_approval_gates", "ALTER TABLE deployment_approval_gates ADD COLUMN policy_version INTEGER"),
        ("ai_use_cases", "ALTER TABLE ai_use_cases ADD COLUMN custom_fields TEXT"),
    ):
        column = statement.rsplit(" ADD COLUMN ", 1)[1].split(" ")[0]
        if not _has_column(connection, table, column):
            connection.execute(statement)
    # routing for the recertification tasks the maintenance worker opens
    # (idempotent; also reaches installs that recorded the baseline earlier)
    seed_review_queue_policies(connection)
    # the vendor governance detection rule, for the same reason
    for rule in VENDOR_RISK_RULES:
        connection.execute(
            """
            INSERT OR IGNORE INTO risk_rules (rule_id, name, signal, severity, framework_refs, rationale)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                rule["rule_id"],
                rule["name"],
                rule["signal"],
                rule["severity"],
                encode_json(rule["framework_refs"]),
                rule["rationale"],
            ),
        )


MIGRATIONS: list[Migration] = [
    Migration(1, "baseline schema", _baseline),
    Migration(2, "indexes for agent posture, audit actions, risk rules", _0002_event_ingest_indexes),
    Migration(3, "SAML 2.0 configuration and request state", _0003_saml),
    Migration(4, "per-IP login throttling", _0004_login_throttle),
    Migration(5, "evidence attestation keys", _0005_attestation_keys),
    Migration(6, "inbound leads from the landing page", _0006_leads),
    Migration(7, "notification outbox, webhooks, invites", _0007_notifications),
    Migration(8, "outbox delivery claims for multi-replica workers", _0008_outbox_claims),
    Migration(9, "tenant-scoped config tables (control library, risk rules, routing, owner policies)", _0009_config_table_tenancy),
    Migration(10, "tenant-scoped record keys (deployments, incidents, prompts, event dedup)", _0010_cross_tenant_keys),
    Migration(11, "audit-chain HMAC anchor column", _0011_audit_hmac),
    Migration(12, "drop fabricated confidence score from risk tables", _0012_drop_risk_confidence),
    Migration(13, "drop leads table (landing-page lead capture removed)", _0013_drop_leads),
    Migration(14, "per-organization telemetry retention window", _0014_org_retention_window),
    Migration(15, "versioned audit-chain hash algorithm", _0015_audit_hash_version),
    Migration(16, "server-stamped ingest time on raw events", _0016_event_ingested_at),
    Migration(17, "audit-chain hmac key id for rotation", _0017_audit_hmac_key_id),
    Migration(18, "session activity timestamp for idle timeout", _0018_session_last_seen),
    Migration(19, "totp multi-factor authentication", _0019_mfa),
    Migration(20, "per-organization mfa requirement", _0020_org_require_mfa),
    Migration(21, "workflow and system indexes for the detail views", _0021_detail_view_indexes),
    Migration(22, "governance policy engine (policies, approval stages, vendor registry)", _0022_governance_policy_engine),
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
    """apply all pending migrations in order, returning the versions applied

    guarded by a cross-replica advisory lock: a replica that loses the race
    waits, then re-reads schema_migrations and finds nothing pending
    """
    with _migration_lock():
        return _apply_pending()


def _apply_pending() -> list[int]:
    applied: list[int] = []
    # re-check inside the lock: another replica may have applied everything while
    # we waited
    for migration in pending_migrations():
        if migration.version == 1:
            # the baseline initializers manage their own connections
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

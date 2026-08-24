"""data retention and right-to-erasure

purge a tenant's data on offboarding and enforce a retention window on telemetry
audit_logs is intentionally not purged: it is retained under records-retention,
and deleting rows would break the hash chain that proves its integrity
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .raw_events import connect

# every tenant-scoped table except audit_logs (retained) and organizations
# (the tenant record, removed last)
_TENANT_SCOPED_TABLES = (
    "sdk_events",
    "governance_applications",
    "governance_workflows",
    "governance_models",
    "governance_providers",
    "governance_observed_events",
    "governance_risks",
    "governance_controls",
    "control_assessments",
    "risk_findings",
    "lifecycle_fingerprints",
    "change_events",
    "review_tasks",
    "prompt_templates",
    "prompt_versions",
    "governance_deployments",
    "deployment_versions",
    "deployment_approval_gates",
    "governance_incidents",
    "ai_use_cases",
    "governance_decisions",
    "governance_exceptions",
    "owner_assignments",
    "role_assignments",
    "ingestion_keys",
    "agent_registry",
    "attestation_keys",
    "invites",
    "notification_outbox",
    "webhooks",
    "saml_configurations",
    "saml_requests",
    "scim_tokens",
    "sso_configurations",
    "sso_login_states",
    # config overrides carry the tenant's id (platform defaults are tenant_id '')
    "control_library",
    "risk_rules",
    "review_queue_policies",
    "owner_assignment_policies",
    "platform_users",
)


def purge_tenant_data(tenant_id: str) -> dict[str, int]:
    """permanently delete all data for a tenant, returning per-table row counts

    also removes sessions and login-attempt records for the tenant's users, then
    the organization record; the audit log is preserved
    """
    counts: dict[str, int] = {}
    with connect() as connection:
        users = connection.execute(
            "SELECT user_ref, email FROM platform_users WHERE tenant_id = ?", (tenant_id,)
        ).fetchall()
        user_refs = [row["user_ref"] for row in users]
        emails = [row["email"] for row in users if row["email"]]

        # sessions and login attempts are keyed by user/email, not tenant_id
        for user_ref in user_refs:
            cur = connection.execute("DELETE FROM sessions WHERE user_ref = ?", (user_ref,))
            counts["sessions"] = counts.get("sessions", 0) + (cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0)
        for email in emails:
            connection.execute("DELETE FROM login_throttle WHERE subject = ?", (f"email:{email.strip().lower()}",))

        for table in _TENANT_SCOPED_TABLES:
            cur = connection.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))
            counts[table] = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

        cur = connection.execute("DELETE FROM organizations WHERE tenant_id = ?", (tenant_id,))
        counts["organizations"] = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    return counts


def purge_events_older_than(retention_days: int, tenant_id: str | None = None) -> int:
    """delete raw sdk events older than the retention window, returning the count;
    derived governance entities are retained, only the raw stream is aged out

    scoped to one organization when tenant_id is given; without it every
    organization's events are aged out, which is only ever what a platform
    operator running a single-tenant install wants
    """
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    with connect() as connection:
        if tenant_id is None:
            cur = connection.execute("DELETE FROM sdk_events WHERE timestamp < ?", (cutoff,))
        else:
            cur = connection.execute(
                "DELETE FROM sdk_events WHERE timestamp < ? AND tenant_id = ?", (cutoff, tenant_id)
            )
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0


# a window this short is almost always a typo (days vs hours) and the deletion
# cannot be undone, so it is rejected rather than honoured
MIN_RETENTION_DAYS = 7


def set_retention_days(tenant_id: str, retention_days: int | None) -> dict[str, Any]:
    """set or clear an organization's retention window; None keeps everything"""
    if retention_days is not None and retention_days < MIN_RETENTION_DAYS:
        raise ValueError(f"retention_days must be at least {MIN_RETENTION_DAYS}, or null to keep everything")
    with connect() as connection:
        cur = connection.execute(
            "UPDATE organizations SET retention_days = ?, updated_at = datetime('now') WHERE tenant_id = ?",
            (retention_days, tenant_id),
        )
        if not cur.rowcount:
            raise ValueError("organization not found")
    return {"tenant_id": tenant_id, "retention_days": retention_days}


def retention_days_for(tenant_id: str) -> int | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT retention_days FROM organizations WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
    return None if row is None or row["retention_days"] is None else int(row["retention_days"])


def tenants_with_retention_window() -> list[dict[str, Any]]:
    """organizations that have opted into ageing their telemetry out"""
    with connect() as connection:
        rows = connection.execute(
            "SELECT tenant_id, retention_days FROM organizations "
            "WHERE retention_days IS NOT NULL AND status = 'active'"
        ).fetchall()
    return [{"tenant_id": row["tenant_id"], "retention_days": int(row["retention_days"])} for row in rows]


def tenant_data_summary(tenant_id: str) -> dict[str, Any]:
    """row counts of a tenant's data across scoped tables, for an offboarding
    preview before an irreversible purge"""
    summary: dict[str, int] = {}
    with connect() as connection:
        for table in _TENANT_SCOPED_TABLES:
            row = connection.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            if row["n"]:
                summary[table] = int(row["n"])
    return {"tenant_id": tenant_id, "row_counts": summary, "total_rows": sum(summary.values())}

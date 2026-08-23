"""Data retention and right-to-erasure.

Enterprise and health-system buyers require the ability to purge a tenant's data
on offboarding (GDPR Art 17 erasure, CCPA deletion, HIPAA/BAA return-or-destroy)
and to enforce a retention window on telemetry (audit finding H-10). Previously
the only DELETE statements in the platform were for expired sessions.

The tamper-evident audit log (audit_logs) is intentionally NOT purged here: it is
retained under the legal-basis/records-retention exception, and deleting rows
would break the hash chain that proves its integrity. A future enhancement can
seal, export, and then rotate per-tenant audit segments.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .raw_events import connect

# Every tenant-scoped table except audit_logs (retained) and organizations
# (the tenant record itself, removed last).
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
    "platform_users",
)


def purge_tenant_data(tenant_id: str) -> dict[str, int]:
    """Permanently delete all data for a tenant. Returns per-table row counts.

    Also removes sessions and login-attempt records for the tenant's users, and
    finally the organization record. The audit log is preserved.
    """
    counts: dict[str, int] = {}
    with connect() as connection:
        users = connection.execute(
            "SELECT user_ref, email FROM platform_users WHERE tenant_id = ?", (tenant_id,)
        ).fetchall()
        user_refs = [row["user_ref"] for row in users]
        emails = [row["email"] for row in users if row["email"]]

        # Sessions and login attempts are keyed by user/email, not tenant_id.
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


def purge_events_older_than(retention_days: int) -> int:
    """Delete raw SDK events older than the retention window. Returns the count.

    Governance entities derived from those events are retained (they are the
    durable inventory); only the raw event stream is aged out.
    """
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    with connect() as connection:
        cur = connection.execute("DELETE FROM sdk_events WHERE timestamp < ?", (cutoff,))
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0


def tenant_data_summary(tenant_id: str) -> dict[str, Any]:
    """Row counts of a tenant's data across scoped tables, for an offboarding
    preview before an irreversible purge."""
    summary: dict[str, int] = {}
    with connect() as connection:
        for table in _TENANT_SCOPED_TABLES:
            row = connection.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            if row["n"]:
                summary[table] = int(row["n"])
    return {"tenant_id": tenant_id, "row_counts": summary, "total_rows": sum(summary.values())}

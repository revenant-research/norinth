# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from . import db
from .entities import entity_id
from .errors import RecordNotFound
from .raw_events import connect
from .scoping import count_scoped_rows, scoped_rows


def init_workflow() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS platform_users (
                user_ref TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        # credential and tenancy columns added incrementally so existing
        # deployments upgrade in place
        for statement in (
            "ALTER TABLE platform_users ADD COLUMN email TEXT",
            "ALTER TABLE platform_users ADD COLUMN password_hash TEXT",
            "ALTER TABLE platform_users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE platform_users ADD COLUMN platform_role TEXT",
            "ALTER TABLE platform_users ADD COLUMN tenant_id TEXT",
        ):
            try:
                connection.execute(statement)
            except db.OperationalError:
                pass
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_ref TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS permissions (
                permission TEXT PRIMARY KEY,
                description TEXT NOT NULL
            )
            """
        )
        # what a role may do is deliberately platform-wide, not per-organization:
        # one install carries one definition of "governance admin" so the same
        # decision means the same thing in every organization on it. only a
        # platform administrator can change it, so no organization can widen its
        # own permissions. an organization that needs different rules runs its
        # own install. who holds a role is per-organization (role_assignments)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS role_permissions (
                role TEXT NOT NULL,
                permission TEXT NOT NULL,
                PRIMARY KEY (role, permission)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS role_assignments (
                role_assignment_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT,
                environment TEXT,
                user_ref TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_queue_policies (
                tenant_id TEXT NOT NULL DEFAULT '',
                policy_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                assigned_role TEXT NOT NULL,
                due_days INTEGER NOT NULL,
                escalation_days INTEGER NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, policy_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS owner_assignment_policies (
                tenant_id TEXT NOT NULL DEFAULT '',
                policy_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                owner_role TEXT NOT NULL,
                applies_to_status TEXT,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, policy_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS owner_assignments (
                owner_assignment_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                owner_role TEXT NOT NULL,
                owner_ref TEXT,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_decisions (
                decision_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                rationale TEXT NOT NULL,
                actor_ref TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_exceptions (
                exception_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                compensating_control TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                actor_ref TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        for statement in (
            "ALTER TABLE review_tasks ADD COLUMN assigned_role TEXT",
            "ALTER TABLE review_tasks ADD COLUMN assigned_to TEXT",
            "ALTER TABLE review_tasks ADD COLUMN due_at TEXT",
            "ALTER TABLE review_tasks ADD COLUMN escalation_status TEXT NOT NULL DEFAULT 'unassigned'",
            "ALTER TABLE review_tasks ADD COLUMN escalated_at TEXT",
        ):
            try:
                connection.execute(statement)
            except db.OperationalError:
                pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_platform_users_status ON platform_users(status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_scope ON role_assignments(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_review_queue_policies_type ON review_queue_policies(task_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_owner_assignment_policies_subject ON owner_assignment_policies(subject_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_owner_assignments_scope ON owner_assignments(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_governance_decisions_scope ON governance_decisions(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_governance_exceptions_scope ON governance_exceptions(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_platform_users_email ON platform_users(email)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_platform_users_tenant ON platform_users(tenant_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_ref)")
        seed_role_permissions(connection)
        seed_review_queue_policies(connection)


# default routing so reviews reach a named person; org admins can change these
DEFAULT_REVIEW_QUEUE_POLICIES: list[dict[str, Any]] = [
    {"policy_id": "default-intake", "task_type": "intake_review", "assigned_role": "governance_reviewer", "due_days": 5, "escalation_days": 3},
    {"policy_id": "default-material-change", "task_type": "material_change_review", "assigned_role": "governance_admin", "due_days": 3, "escalation_days": 2},
]


def seed_review_queue_policies(connection) -> None:
    for policy in DEFAULT_REVIEW_QUEUE_POLICIES:
        connection.execute(
            """
            INSERT INTO review_queue_policies (tenant_id, policy_id, task_type, assigned_role, due_days, escalation_days, source, created_at, updated_at)
            VALUES ('', ?, ?, ?, ?, ?, 'default', datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id, policy_id) DO NOTHING
            """,
            (policy["policy_id"], policy["task_type"], policy["assigned_role"], policy["due_days"], policy["escalation_days"]),
        )


# default role-to-permission grants; super admins bypass the permission model
# entirely (see authorization.py) so they're not listed
DEFAULT_PERMISSIONS: dict[str, str] = {
    "org.manage": "Provision and suspend organizations and their first administrator",
    "user.manage": "Create and update users within an organization",
    "role.assign": "Assign and revoke roles for users within an organization",
    "config.write": "Create and update governance policies, controls, and risk rules",
    "intake.submit": "Submit and risk-tier AI use cases",
    "owner.assign": "Assign accountable owners to applications, risks, and incidents",
    "review.decide": "Record reviewer decisions on review tasks",
    "risk.accept": "Accept risk and create exceptions with compensating controls",
    "gate.decide": "Approve or reject deployment release gates",
    "incident.close": "Close incidents with a documented closure record",
    "lifecycle.manage": "Recertify and retire AI use cases",
}

DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "org_admin": {"user.manage", "role.assign", "config.write", "owner.assign", "intake.submit", "lifecycle.manage"},
    "governance_admin": {
        "config.write",
        "intake.submit",
        "owner.assign",
        "review.decide",
        "risk.accept",
        "gate.decide",
        "incident.close",
        "lifecycle.manage",
    },
    "risk_owner": {"review.decide", "risk.accept", "owner.assign"},
    "control_owner": {"review.decide", "owner.assign"},
    "governance_reviewer": {"review.decide"},
    # read-only: authenticate and view, no decision or config rights
    "governance_viewer": set(),
}


def seed_role_permissions(connection) -> None:
    for permission, description in DEFAULT_PERMISSIONS.items():
        connection.execute(
            "INSERT OR IGNORE INTO permissions (permission, description) VALUES (?, ?)",
            (permission, description),
        )
    for role, permissions in DEFAULT_ROLE_PERMISSIONS.items():
        for permission in permissions:
            connection.execute(
                "INSERT OR IGNORE INTO role_permissions (role, permission) VALUES (?, ?)",
                (role, permission),
            )


def _in_scopes(row: dict[str, Any], wanted: set[tuple] | None) -> bool:
    if wanted is None:
        return True
    return (row.get("tenant_id"), row.get("project"), row.get("environment"), row.get("application_name")) in wanted


def refresh_workflow_state(scopes: list[dict[str, Any]] | None = None) -> None:
    """apply owner policies and refresh the review queue; scopes limits to the
    apps an ingest touched, None refreshes everything"""
    wanted = None if scopes is None else {(s.get("tenant_id"), s["project"], s["environment"], s["application_name"]) for s in scopes}
    tenant_filter = None if scopes is None else {s.get("tenant_id") for s in scopes}
    with connect() as connection:
        applications = connection.execute(
            "SELECT DISTINCT tenant_id, project, environment, application_name FROM governance_applications"
        ).fetchall()
        policy_cache: dict[str, list[dict[str, Any]]] = {}
        queue_cache: dict[str, list[dict[str, Any]]] = {}

        def owner_policies_for(tid: str | None) -> list[dict[str, Any]]:
            key = tid or ""
            if key not in policy_cache:
                policy_cache[key] = list_owner_policies(connection, key)
            return policy_cache[key]

        for application in applications:
            app_context = dict(application)
            if not _in_scopes(app_context, wanted):
                continue
            apply_owner_policies(connection, app_context, owner_policies_for(app_context.get("tenant_id")), "application", app_context["application_name"], "active")
        for row in connection.execute("SELECT DISTINCT tenant_id, project, environment, application_name, risk, finding_id FROM risk_findings").fetchall():
            app_context = dict(row)
            if not _in_scopes(app_context, wanted):
                continue
            apply_owner_policies(connection, app_context, owner_policies_for(app_context.get("tenant_id")), "risk_finding", row["finding_id"], "open")
        for row in connection.execute("SELECT DISTINCT tenant_id, project, environment, application_name, control_id, assessment_id FROM control_assessments WHERE status = 'missing'").fetchall():
            app_context = dict(row)
            if not _in_scopes(app_context, wanted):
                continue
            apply_owner_policies(connection, app_context, owner_policies_for(app_context.get("tenant_id")), "control_assessment", row["assessment_id"], "missing")
        for row in connection.execute("SELECT DISTINCT tenant_id, project, environment, application_name, incident_id, status FROM governance_incidents WHERE status != 'closed'").fetchall():
            app_context = dict(row)
            if not _in_scopes(app_context, wanted):
                continue
            apply_owner_policies(connection, app_context, owner_policies_for(app_context.get("tenant_id")), "incident", row["incident_id"], row["status"])
        refresh_review_queue(connection, queue_cache, tenant_filter)


def list_queue_policies(connection, tenant_id: str | None = None) -> list[dict[str, Any]]:
    tid = tenant_id or ""
    rows = connection.execute("SELECT * FROM review_queue_policies WHERE tenant_id IN ('', ?) ORDER BY policy_id", (tid,)).fetchall()
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        record = dict(row)
        if record["policy_id"] not in merged or record["tenant_id"] != "":
            merged[record["policy_id"]] = record
    return list(merged.values())


def refresh_review_queue(connection, queue_cache: dict[str, list[dict[str, Any]]], tenant_filter: set | None = None) -> None:
    for task in connection.execute("SELECT * FROM review_tasks WHERE status = 'open'").fetchall():
        task_record = dict(task)
        if tenant_filter is not None and task_record.get("tenant_id") not in tenant_filter:
            continue
        tid = task_record.get("tenant_id") or ""
        if tid not in queue_cache:
            queue_cache[tid] = list_queue_policies(connection, tid)
        policy = next((item for item in queue_cache[tid] if item["task_type"] == task_record["task_type"]), None)
        if policy is None:
            mark_review_task_queue_state(connection, task_record, None, None, None, "unassigned")
            continue
        assignee = find_assignee(connection, task_record, policy["assigned_role"])
        due_at = _shift_days(task_record["created_at"], int(policy["due_days"]))
        escalation_status = queue_status(connection, due_at, int(policy["escalation_days"]), assignee)
        mark_review_task_queue_state(connection, task_record, policy["assigned_role"], assignee, due_at, escalation_status)


def find_assignee(connection, task: dict[str, Any], assigned_role: str) -> str | None:
    row = connection.execute(
        """
        SELECT role_assignments.user_ref
        FROM role_assignments
        JOIN platform_users ON platform_users.user_ref = role_assignments.user_ref
        WHERE role_assignments.role = ?
          AND role_assignments.status = 'active'
          AND platform_users.status = 'active'
          AND (role_assignments.tenant_id IS NULL OR role_assignments.tenant_id = ?)
          AND (role_assignments.project IS NULL OR role_assignments.project = ?)
          AND (role_assignments.environment IS NULL OR role_assignments.environment = ?)
        ORDER BY
          CASE WHEN role_assignments.tenant_id IS NULL THEN 1 ELSE 0 END,
          CASE WHEN role_assignments.project IS NULL THEN 1 ELSE 0 END,
          CASE WHEN role_assignments.environment IS NULL THEN 1 ELSE 0 END,
          role_assignments.created_at ASC
        LIMIT 1
        """,
        (assigned_role, task.get("tenant_id"), task["project"], task["environment"]),
    ).fetchone()
    return None if row is None else row["user_ref"]


def _parse_ts(value: str) -> datetime:
    """parse the timestamp formats the platform writes: 'YYYY-MM-DD HH:MM:SS' and
    iso-8601; naive values are treated as utc"""
    text = str(value).strip().replace(" ", "T", 1) if " " in str(value) and "T" not in str(value) else str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _shift_days(value: str, days: int) -> str:
    return (_parse_ts(value) + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def queue_status(connection, due_at: str, escalation_days: int, assignee: str | None) -> str:
    # date arithmetic in python, not sql, so it's identical on every backend
    if assignee is None:
        return "unassigned"
    now = datetime.now(UTC)
    if now <= _parse_ts(due_at):
        return "on_track"
    escalated_at = _parse_ts(due_at) + timedelta(days=escalation_days)
    return "escalated" if now > escalated_at else "overdue"


def _notify_queue_transition(connection, task, assigned_role, assigned_to, due_at, escalation_status) -> None:
    """emit notifications only on transitions (newly assigned/overdue/escalated);
    queue refresh runs on every ingest, so compare with the stored row to avoid
    repeating"""
    from app.services.notifications import emit, public_base_url

    tenant_id = task.get("tenant_id")
    link = f"{public_base_url()}/#review/{task['task_id']}"
    title = task.get("title") or task.get("task_type") or task["task_id"]
    if assigned_to and assigned_to != task.get("assigned_to"):
        emit(
            connection,
            tenant_id=tenant_id,
            event_type="review.assigned",
            subject=f"Review assigned to you: {title}",
            text=f"A {task.get('task_type', 'review')} for {task.get('application_name')} is routed to you as {assigned_role}. Due {due_at}.",
            data={"task_id": task["task_id"], "task_type": task.get("task_type"), "application_name": task.get("application_name"), "due_at": due_at},
            to_users=[assigned_to],
            link=link,
        )
    previous = task.get("escalation_status")
    if escalation_status == "overdue" and previous not in {"overdue", "escalated"}:
        emit(
            connection,
            tenant_id=tenant_id,
            event_type="review.overdue",
            subject=f"Review overdue: {title}",
            text=f"The {task.get('task_type', 'review')} for {task.get('application_name')} was due {due_at} and has not been decided.",
            data={"task_id": task["task_id"], "assigned_to": assigned_to, "due_at": due_at},
            to_users=[assigned_to] if assigned_to else [],
            link=link,
        )
    if escalation_status == "escalated" and previous != "escalated":
        emit(
            connection,
            tenant_id=tenant_id,
            event_type="review.escalated",
            subject=f"Review escalated: {title}",
            text=f"The {task.get('task_type', 'review')} for {task.get('application_name')} assigned to {assigned_to or 'nobody'} is past its escalation deadline (due {due_at}). An administrator should reassign or decide it.",
            data={"task_id": task["task_id"], "assigned_to": assigned_to, "due_at": due_at},
            to_users=[assigned_to] if assigned_to else [],
            to_roles=["org_admin"],
            link=link,
        )


def mark_review_task_queue_state(
    connection,
    task: dict[str, Any],
    assigned_role: str | None,
    assigned_to: str | None,
    due_at: str | None,
    escalation_status: str,
) -> None:
    escalated_at = None
    if escalation_status == "escalated":
        escalated_at = connection.execute("SELECT datetime('now') AS now").fetchone()["now"]
    _notify_queue_transition(connection, task, assigned_role, assigned_to, due_at, escalation_status)
    connection.execute(
        """
        UPDATE review_tasks
        SET assigned_role = ?, assigned_to = ?, due_at = ?, escalation_status = ?, escalated_at = COALESCE(escalated_at, ?), updated_at = datetime('now')
        WHERE task_id = ?
        """,
        (assigned_role, assigned_to, due_at, escalation_status, escalated_at, task["task_id"]),
    )


def list_owner_policies(connection, tenant_id: str | None = None) -> list[dict[str, Any]]:
    tid = tenant_id or ""
    rows = connection.execute("SELECT * FROM owner_assignment_policies WHERE tenant_id IN ('', ?) ORDER BY policy_id", (tid,)).fetchall()
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        record = dict(row)
        if record["policy_id"] not in merged or record["tenant_id"] != "":
            merged[record["policy_id"]] = record
    return list(merged.values())


def apply_owner_policies(
    connection,
    app_context: dict[str, Any],
    policies: list[dict[str, Any]],
    subject_type: str,
    subject_name: str,
    subject_status: str,
) -> None:
    for policy in policies:
        if policy["subject_type"] != subject_type:
            continue
        if policy["applies_to_status"] and policy["applies_to_status"] != subject_status:
            continue
        ensure_owner_assignment(connection, app_context, subject_type, subject_name, policy["owner_role"], policy["source"])


def ensure_owner_assignment(connection, app_context: dict[str, Any], subject_type: str, subject_name: str, owner_role: str, source: str) -> None:
    assignment_id = entity_id(
        "owner-assignment",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        subject_type,
        subject_name,
        owner_role,
    )
    connection.execute(
        """
        INSERT INTO owner_assignments (
            owner_assignment_id, tenant_id, project, environment, application_name,
            subject_type, subject_name, owner_role, owner_ref, status, source, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'unassigned', ?, datetime('now'), datetime('now'))
        ON CONFLICT(owner_assignment_id) DO NOTHING
        """,
        (
            assignment_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            subject_type,
            subject_name,
            owner_role,
            source,
        ),
    )


def upsert_owner_policy(policy: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    if not tenant_id:
        raise ValueError("a tenant_id is required to customize owner policies")
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO owner_assignment_policies (
                tenant_id, policy_id, subject_type, owner_role, applies_to_status, source, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT (tenant_id, policy_id) DO UPDATE SET
                subject_type=excluded.subject_type, owner_role=excluded.owner_role,
                applies_to_status=excluded.applies_to_status, source=excluded.source, updated_at=datetime('now')
            """,
            (
                tenant_id,
                policy["policy_id"],
                policy["subject_type"],
                policy["owner_role"],
                policy.get("applies_to_status"),
                policy["source"],
            ),
        )
    return policy


def upsert_platform_user(user: dict[str, Any]) -> dict[str, Any]:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO platform_users (user_ref, display_name, status, created_at, updated_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(user_ref) DO UPDATE SET
                display_name=excluded.display_name,
                status=excluded.status,
                updated_at=datetime('now')
            """,
            (user["user_ref"], user["display_name"], user["status"]),
        )
    return user


def create_platform_user(
    *,
    user_ref: str,
    display_name: str,
    email: str,
    password_hash: str,
    status: str = "active",
    platform_role: str | None = None,
    tenant_id: str | None = None,
    must_change_password: bool = True,
) -> dict[str, Any]:
    """create or update a credentialed user"""
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO platform_users (
                user_ref, display_name, status, email, password_hash,
                must_change_password, platform_role, tenant_id, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(user_ref) DO UPDATE SET
                display_name=excluded.display_name,
                status=excluded.status,
                email=excluded.email,
                password_hash=excluded.password_hash,
                must_change_password=excluded.must_change_password,
                platform_role=excluded.platform_role,
                tenant_id=excluded.tenant_id,
                updated_at=datetime('now')
            """,
            (
                user_ref,
                display_name,
                status,
                email,
                password_hash,
                1 if must_change_password else 0,
                platform_role,
                tenant_id,
            ),
        )
        return dict(connection.execute("SELECT * FROM platform_users WHERE user_ref = ?", (user_ref,)).fetchone())


def set_user_password(user_ref: str, password_hash: str) -> None:
    """the user chose a new password: store it and clear the forced-change flag"""
    with connect() as connection:
        connection.execute(
            "UPDATE platform_users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE user_ref = ?",
            (password_hash, user_ref),
        )


def upgrade_password_hash(user_ref: str, password_hash: str) -> None:
    """transparently re-hash the same password under stronger KDF params

    unlike set_user_password this must NOT touch must_change_password: the user
    has not chosen a password, so a login that happens to trigger a rehash must
    not clear the forced-change flag on a temporary credential
    """
    with connect() as connection:
        connection.execute(
            "UPDATE platform_users SET password_hash = ?, updated_at = datetime('now') WHERE user_ref = ?",
            (password_hash, user_ref),
        )


def reset_user_password(user_ref: str, password_hash: str) -> None:
    """set a temporary password and force a change on next login"""
    with connect() as connection:
        connection.execute(
            "UPDATE platform_users SET password_hash = ?, must_change_password = 1, updated_at = datetime('now') WHERE user_ref = ?",
            (password_hash, user_ref),
        )


def set_user_status(user_ref: str, status: str) -> dict[str, Any]:
    """activate or deactivate an account; a deactivated user can't authenticate
    (their sessions resolve to an inactive user and are rejected)"""
    with connect() as connection:
        row = connection.execute("SELECT 1 FROM platform_users WHERE user_ref = ?", (user_ref,)).fetchone()
        if row is None:
            raise ValueError("user not found")
        connection.execute(
            "UPDATE platform_users SET status = ?, updated_at = datetime('now') WHERE user_ref = ?",
            (status, user_ref),
        )
        return dict(connection.execute("SELECT * FROM platform_users WHERE user_ref = ?", (user_ref,)).fetchone())


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM platform_users WHERE email = ?", (email,)).fetchone()
    return None if row is None else dict(row)


def count_super_admins() -> int:
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM platform_users WHERE platform_role = 'super_admin'"
        ).fetchone()
    return int(row["count"])


def insert_session(token: str, user_ref: str, expires_at: str) -> None:
    with connect() as connection:
        connection.execute(
            "INSERT INTO sessions (token, user_ref, created_at, expires_at, last_seen_at) VALUES (?, ?, datetime('now'), ?, ?)",
            (token, user_ref, expires_at, datetime.now(UTC).isoformat()),
        )


def load_session(token: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
            (token, datetime.now(UTC).isoformat()),
        ).fetchone()
    return None if row is None else dict(row)


def touch_session(token: str, seen_at: str) -> None:
    """record session activity for the idle timeout"""
    with connect() as connection:
        connection.execute("UPDATE sessions SET last_seen_at = ? WHERE token = ?", (seen_at, token))


def delete_session(token: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM sessions WHERE token = ?", (token,))


def delete_sessions_for_user(user_ref: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM sessions WHERE user_ref = ?", (user_ref,))


def purge_expired_sessions() -> None:
    with connect() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (datetime.now(UTC).isoformat(),))


def list_role_permissions(role: str) -> list[str]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT permission FROM role_permissions WHERE role = ? ORDER BY permission",
            (role,),
        ).fetchall()
    return [row["permission"] for row in rows]


def list_permissions() -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute("SELECT * FROM permissions ORDER BY permission").fetchall()
    return [dict(row) for row in rows]


def list_all_role_permissions() -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute("SELECT role, permission FROM role_permissions ORDER BY role, permission").fetchall()
    return [dict(row) for row in rows]


def set_role_permission(role: str, permission: str, granted: bool) -> None:
    with connect() as connection:
        if granted:
            connection.execute(
                "INSERT OR IGNORE INTO role_permissions (role, permission) VALUES (?, ?)",
                (role, permission),
            )
        else:
            connection.execute(
                "DELETE FROM role_permissions WHERE role = ? AND permission = ?",
                (role, permission),
            )


def upsert_role_assignment(assignment: dict[str, Any]) -> dict[str, Any]:
    assignment_id = entity_id(
        "role-assignment",
        assignment.get("tenant_id"),
        assignment.get("project"),
        assignment.get("environment"),
        assignment["user_ref"],
        assignment["role"],
    )
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO role_assignments (
                role_assignment_id, tenant_id, project, environment, user_ref, role, status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(role_assignment_id) DO UPDATE SET
                status=excluded.status,
                updated_at=datetime('now')
            """,
            (
                assignment_id,
                assignment.get("tenant_id"),
                assignment.get("project"),
                assignment.get("environment"),
                assignment["user_ref"],
                assignment["role"],
                assignment["status"],
            ),
        )
    return {**assignment, "role_assignment_id": assignment_id}


def upsert_review_queue_policy(policy: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    if not tenant_id:
        raise ValueError("a tenant_id is required to customize review routing")
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO review_queue_policies (
                tenant_id, policy_id, task_type, assigned_role, due_days, escalation_days, source, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id, policy_id) DO UPDATE SET
                task_type=excluded.task_type,
                assigned_role=excluded.assigned_role,
                due_days=excluded.due_days,
                escalation_days=excluded.escalation_days,
                source=excluded.source,
                updated_at=datetime('now')
            """,
            (
                tenant_id,
                policy["policy_id"],
                policy["task_type"],
                policy["assigned_role"],
                int(policy["due_days"]),
                int(policy["escalation_days"]),
                policy["source"],
            ),
        )
    return policy


def assign_owner(owner_assignment_id: str, owner_ref: str, actor_ref: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM owner_assignments WHERE owner_assignment_id = ?",
            (owner_assignment_id,),
        ).fetchone()
        if row is None:
            raise RecordNotFound("owner assignment not found")
        connection.execute(
            """
            UPDATE owner_assignments
            SET owner_ref = ?, status = 'assigned', source = ?, updated_at = datetime('now')
            WHERE owner_assignment_id = ?
            """,
            (owner_ref, f"assigned_by:{actor_ref}", owner_assignment_id),
        )
        return dict(connection.execute("SELECT * FROM owner_assignments WHERE owner_assignment_id = ?", (owner_assignment_id,)).fetchone())


def record_decision(target_type: str, target_id: str, decision: str, rationale: str, actor_ref: str) -> dict[str, Any]:
    """append a governance decision; the record is immutable once written

    the id is derived from the decision's content, so a resubmission of the
    identical decision returns the original row — including its original
    created_at, which is evidence of WHEN the call was made and must not move.
    a decision is a record, not a lever: replaying one does not re-apply
    status; changing course takes a new decision (new content, new row)
    """
    target = load_decision_target(target_type, target_id)
    decision_id = entity_id("governance-decision", target_type, target_id, decision, rationale, actor_ref)
    with connect() as connection:
        existing = connection.execute(
            "SELECT * FROM governance_decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        if existing is not None:
            return dict(existing)
        connection.execute(
            """
            INSERT OR IGNORE INTO governance_decisions (
                decision_id, tenant_id, project, environment, application_name, target_type,
                target_id, decision, rationale, actor_ref, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                decision_id,
                target.get("tenant_id"),
                target["project"],
                target["environment"],
                target["application_name"],
                target_type,
                target_id,
                decision,
                rationale,
                actor_ref,
            ),
        )
        apply_decision_status(connection, target_type, target_id, decision)
        return dict(connection.execute("SELECT * FROM governance_decisions WHERE decision_id = ?", (decision_id,)).fetchone())


def load_decision_target(target_type: str, target_id: str) -> dict[str, Any]:
    table_by_target = {
        "review_task": ("review_tasks", "task_id"),
        "risk_finding": ("risk_findings", "finding_id"),
        "change_event": ("change_events", "change_id"),
        "control_assessment": ("control_assessments", "assessment_id"),
        "deployment_gate": ("deployment_approval_gates", "gate_id"),
        "incident": ("governance_incidents", "incident_id"),
    }
    if target_type not in table_by_target:
        raise ValueError("unsupported decision target type")
    table, id_column = table_by_target[target_type]
    with connect() as connection:
        row = connection.execute(f"SELECT * FROM {table} WHERE {id_column} = ?", (target_id,)).fetchone()
    if row is None:
        raise RecordNotFound("decision target not found")
    return dict(row)


def apply_decision_status(connection, target_type: str, target_id: str, decision: str) -> None:
    status_by_decision = {
        "approve": "approved",
        "reject": "rejected",
        "accept_risk": "accepted",
        "mitigate": "mitigation_required",
        "waive": "waived",
        "close": "closed",
    }
    # an unknown decision maps to no status change rather than being written
    # verbatim as the target's status; the api already rejects unknown decisions
    status = status_by_decision.get(decision)
    if status is None:
        return
    if target_type == "review_task":
        connection.execute("UPDATE review_tasks SET status = ?, updated_at = datetime('now') WHERE task_id = ?", (status, target_id))
        # an intake review decides the use case's lifecycle: approve -> approved,
        # reject -> rejected; other decisions leave it submitted
        task = connection.execute("SELECT task_type, change_id FROM review_tasks WHERE task_id = ?", (target_id,)).fetchone()
        if task is not None and task["task_type"] == "intake_review" and status in {"approved", "rejected"}:
            connection.execute(
                "UPDATE ai_use_cases SET status = ?, updated_at = datetime('now') WHERE intake_id = ?", (status, task["change_id"])
            )
    if target_type == "risk_finding":
        connection.execute("UPDATE risk_findings SET status = ?, evaluated_at = datetime('now') WHERE finding_id = ?", (status, target_id))
    if target_type == "change_event":
        connection.execute("UPDATE change_events SET status = ? WHERE change_id = ?", (status, target_id))
    if target_type == "control_assessment":
        connection.execute("UPDATE control_assessments SET status = ?, evaluated_at = datetime('now') WHERE assessment_id = ?", (status, target_id))
    # deployment gates and incidents are not transitioned here: their status
    # changes go through the guarded set_deployment_gate_status (evidence check +
    # attribution) and set_incident_status, so a generic decision can't flip a
    # gate to "approved" and bypass the evidence check


def create_exception(
    target_type: str,
    target_id: str,
    reason: str,
    compensating_control: str,
    expires_at: str,
    actor_ref: str,
) -> dict[str, Any]:
    target = load_decision_target(target_type, target_id)
    exception_id = entity_id("governance-exception", target_type, target_id, reason, expires_at)
    with connect() as connection:
        # replaying an identical exception must not resurrect it: the REPLACE
        # form reset a lapsed exception to 'active' and rewrote created_at,
        # falsifying when the waiver was granted. the original row stands;
        # re-waiving after a lapse takes a new expiry, which is a new record
        existing = connection.execute(
            "SELECT * FROM governance_exceptions WHERE exception_id = ?", (exception_id,)
        ).fetchone()
        if existing is not None:
            return dict(existing)
        connection.execute(
            """
            INSERT OR IGNORE INTO governance_exceptions (
                exception_id, tenant_id, project, environment, application_name, target_type,
                target_id, reason, compensating_control, expires_at, status, actor_ref, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'), datetime('now'))
            """,
            (
                exception_id,
                target.get("tenant_id"),
                target["project"],
                target["environment"],
                target["application_name"],
                target_type,
                target_id,
                reason,
                compensating_control,
                expires_at,
                actor_ref,
            ),
        )
        apply_decision_status(connection, target_type, target_id, "waive")
        return dict(connection.execute("SELECT * FROM governance_exceptions WHERE exception_id = ?", (exception_id,)).fetchone())




def list_owner_assignments(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    return scoped_rows(
        "owner_assignments",
        tenant_id=tenant_id,
        project=project,
        environment=environment,
        order_by="updated_at",
        limit=limit,
        offset=offset,
    )


def load_owner_assignment(owner_assignment_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM owner_assignments WHERE owner_assignment_id = ?",
            (owner_assignment_id,),
        ).fetchone()
    if row is None:
        raise RecordNotFound("owner assignment not found")
    return dict(row)


def list_platform_users(*, tenant_id: str | None = None) -> list[dict[str, Any]]:
    with connect() as connection:
        if tenant_id:
            rows = connection.execute(
                "SELECT * FROM platform_users WHERE tenant_id = ? ORDER BY display_name",
                (tenant_id,),
            ).fetchall()
        else:
            rows = connection.execute("SELECT * FROM platform_users ORDER BY display_name").fetchall()
    return [_public_user(dict(row)) for row in rows]


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    """strip credential material before a user record leaves the storage layer"""
    return {key: value for key, value in user.items() if key != "password_hash"}


def load_platform_user(user_ref: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM platform_users WHERE user_ref = ?", (user_ref,)).fetchone()
    return None if row is None else dict(row)


def count_platform_users() -> int:
    with connect() as connection:
        row = connection.execute("SELECT COUNT(*) AS count FROM platform_users").fetchone()
    return int(row["count"])


def count_org_admins() -> int:
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(DISTINCT user_ref) AS count FROM role_assignments WHERE role = 'org_admin' AND status = 'active'"
        ).fetchone()
    return int(row["count"])


def count_users_pending_password() -> int:
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS count FROM platform_users WHERE must_change_password = 1 AND status = 'active'"
        ).fetchone()
    return int(row["count"])


def tenant_user_counts() -> dict[str, int]:
    """accounts per tenant, for the tenant overview"""
    with connect() as connection:
        rows = connection.execute(
            "SELECT tenant_id, COUNT(*) AS count FROM platform_users WHERE tenant_id IS NOT NULL GROUP BY tenant_id"
        ).fetchall()
    return {row["tenant_id"]: int(row["count"]) for row in rows}


def list_role_assignments(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("role_assignments", tenant_id=tenant_id, project=project, environment=environment, order_by="updated_at")


def list_actor_role_assignments(user_ref: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM role_assignments WHERE user_ref = ? AND status = 'active' ORDER BY updated_at DESC",
            (user_ref,),
        ).fetchall()
    return [dict(row) for row in rows]


def count_active_role_assignments(role: str | None = None) -> int:
    clause = "WHERE status = 'active'"
    params: tuple[str, ...] = ()
    if role:
        clause = f"{clause} AND role = ?"
        params = (role,)
    with connect() as connection:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM role_assignments {clause}", params).fetchone()
    return int(row["count"])


def list_review_queue_policies() -> list[dict[str, Any]]:
    with connect() as connection:
        return list_queue_policies(connection)


def list_configured_owner_policies() -> list[dict[str, Any]]:
    with connect() as connection:
        return list_owner_policies(connection)


def list_decisions(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    return scoped_rows(
        "governance_decisions",
        tenant_id=tenant_id,
        project=project,
        environment=environment,
        order_by="created_at",
        limit=limit,
        offset=offset,
    )


def expire_due_exceptions() -> int:
    """mark active exceptions past expires_at as 'expired' and reopen the finding
    they waived, so it re-enters the risk register; idempotent"""
    now = datetime.now(UTC).isoformat()
    expired = 0
    with connect() as connection:
        due = connection.execute(
            "SELECT exception_id, target_type, target_id FROM governance_exceptions WHERE status = 'active' AND expires_at <= ?",
            (now,),
        ).fetchall()
        for row in due:
            connection.execute(
                "UPDATE governance_exceptions SET status = 'expired', updated_at = datetime('now') WHERE exception_id = ?",
                (row["exception_id"],),
            )
            # reopen the waived target so the next recompute re-evaluates it
            if row["target_type"] == "risk_finding":
                connection.execute(
                    "UPDATE risk_findings SET status = 'open', evaluated_at = datetime('now') WHERE finding_id = ? AND status = 'waived'",
                    (row["target_id"],),
                )
            elif row["target_type"] == "control_assessment":
                connection.execute(
                    "UPDATE control_assessments SET status = 'missing', evaluated_at = datetime('now') WHERE assessment_id = ? AND status = 'waived'",
                    (row["target_id"],),
                )
            expired += 1
    return expired


def list_exceptions(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    return scoped_rows(
        "governance_exceptions",
        tenant_id=tenant_id,
        project=project,
        environment=environment,
        order_by="updated_at",
        limit=limit,
        offset=offset,
    )


def count_owner_assignments(
    *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None
) -> int:
    return count_scoped_rows("owner_assignments", tenant_id=tenant_id, project=project, environment=environment)


def count_decisions(
    *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None
) -> int:
    return count_scoped_rows("governance_decisions", tenant_id=tenant_id, project=project, environment=environment)


def count_exceptions(
    *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None
) -> int:
    return count_scoped_rows("governance_exceptions", tenant_id=tenant_id, project=project, environment=environment)

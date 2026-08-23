"""SCIM 2.0 Groups and group -> role mapping.

Enterprises grant access through IdP groups ("Norinth-Reviewers",
"Norinth-Admins"), not by hand-assigning roles per user. This module stores the
groups an identity provider pushes, the organization's mapping from group name
to Norinth role, and -- crucially -- which role assignments were granted *by*
group membership, so that removing someone from a group revokes exactly the
role the group granted and never a role an administrator assigned by hand.

Reconciliation rules (see ``reconcile_user_roles``):
* Desired roles = mapped roles of the groups the user is currently in.
* Roles are granted only if the result would not put an administration role
  and a governance-decision role on the same person (separation of duties,
  audit C-4). A conflicting set grants *nothing* from the conflicting side and
  is audit-logged, rather than silently picking one.
* Group-granted roles no longer desired are revoked. Manually granted roles
  are untouched.
* The last active org_admin of an organization is never revoked by group
  membership (no IdP-driven lockout); this is audit-logged instead.
"""

from __future__ import annotations

import secrets
from typing import Any

from app.services.authorization import ADMINISTRATION_ROLES, DECISION_ROLES, ORG_ADMIN

from .audit import record_audit
from .raw_events import connect
from .workflow import list_role_assignments, upsert_role_assignment


def ensure_scim_group_tables(connection) -> None:
    """Schema for migration 6 (idempotent)."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scim_groups (
            group_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            external_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant_name ON scim_groups (tenant_id, display_name)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scim_group_members (
            group_id TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            PRIMARY KEY (group_id, user_ref)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scim_role_mappings (
            tenant_id TEXT NOT NULL,
            group_name_lower TEXT NOT NULL,
            group_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, group_name_lower)
        )
        """
    )
    # Which (user, role) pairs were granted because of group membership.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scim_managed_roles (
            tenant_id TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            role TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, user_ref, role)
        )
        """
    )


# --- groups -----------------------------------------------------------------------


def create_group(tenant_id: str, display_name: str, external_id: str | None) -> dict[str, Any]:
    group_id = "grp_" + secrets.token_urlsafe(9)
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO scim_groups (group_id, tenant_id, display_name, external_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (group_id, tenant_id, display_name, external_id),
        )
    return load_group(group_id, tenant_id)  # type: ignore[return-value]


def load_group(group_id: str, tenant_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM scim_groups WHERE group_id = ? AND tenant_id = ?", (group_id, tenant_id)
        ).fetchone()
        if row is None:
            return None
        members = connection.execute(
            "SELECT user_ref FROM scim_group_members WHERE group_id = ? ORDER BY user_ref", (group_id,)
        ).fetchall()
    return {**dict(row), "members": [m["user_ref"] for m in members]}


def find_group_by_name(tenant_id: str, display_name: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT group_id FROM scim_groups WHERE tenant_id = ? AND lower(display_name) = lower(?)",
            (tenant_id, display_name),
        ).fetchone()
    return None if row is None else load_group(row["group_id"], tenant_id)


def list_groups(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT group_id FROM scim_groups WHERE tenant_id = ? ORDER BY display_name", (tenant_id,)
        ).fetchall()
    return [load_group(row["group_id"], tenant_id) for row in rows]  # type: ignore[misc]


def rename_group(group_id: str, tenant_id: str, display_name: str, external_id: str | None) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE scim_groups SET display_name = ?, external_id = COALESCE(?, external_id), updated_at = datetime('now') "
            "WHERE group_id = ? AND tenant_id = ?",
            (display_name, external_id, group_id, tenant_id),
        )


def set_group_members(group_id: str, members: set[str]) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM scim_group_members WHERE group_id = ?", (group_id,))
        for user_ref in sorted(members):
            connection.execute(
                "INSERT INTO scim_group_members (group_id, user_ref) VALUES (?, ?)", (group_id, user_ref)
            )
        connection.execute("UPDATE scim_groups SET updated_at = datetime('now') WHERE group_id = ?", (group_id,))


def delete_group(group_id: str, tenant_id: str) -> list[str]:
    """Remove the group; return the members that were in it (to reconcile)."""
    group = load_group(group_id, tenant_id)
    if group is None:
        return []
    with connect() as connection:
        connection.execute("DELETE FROM scim_group_members WHERE group_id = ?", (group_id,))
        connection.execute("DELETE FROM scim_groups WHERE group_id = ? AND tenant_id = ?", (group_id, tenant_id))
    return list(group["members"])


def user_groups(tenant_id: str, user_ref: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT g.group_id, g.display_name
            FROM scim_groups g JOIN scim_group_members m ON m.group_id = g.group_id
            WHERE g.tenant_id = ? AND m.user_ref = ?
            ORDER BY g.display_name
            """,
            (tenant_id, user_ref),
        ).fetchall()
    return [dict(row) for row in rows]


# --- mappings -----------------------------------------------------------------------


def list_role_mappings(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT group_name, role, created_by, created_at, updated_at FROM scim_role_mappings WHERE tenant_id = ? ORDER BY group_name",
            (tenant_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def upsert_role_mapping(tenant_id: str, group_name: str, role: str, created_by: str | None) -> dict[str, Any]:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO scim_role_mappings (tenant_id, group_name_lower, group_name, role, created_by, created_at, updated_at)
            VALUES (?, lower(?), ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id, group_name_lower) DO UPDATE SET
                group_name = excluded.group_name, role = excluded.role, updated_at = datetime('now')
            """,
            (tenant_id, group_name, group_name, role, created_by),
        )
    return {"group_name": group_name, "role": role}


def delete_role_mapping(tenant_id: str, group_name: str) -> bool:
    with connect() as connection:
        cursor = connection.execute(
            "DELETE FROM scim_role_mappings WHERE tenant_id = ? AND group_name_lower = lower(?)", (tenant_id, group_name)
        )
        return bool(cursor.rowcount)


def _mapped_roles_for_groups(tenant_id: str, group_names: list[str]) -> set[str]:
    if not group_names:
        return set()
    with connect() as connection:
        rows = connection.execute(
            "SELECT group_name_lower, role FROM scim_role_mappings WHERE tenant_id = ?", (tenant_id,)
        ).fetchall()
    mapping = {row["group_name_lower"]: row["role"] for row in rows}
    return {mapping[name.lower()] for name in group_names if name.lower() in mapping}


# --- reconciliation ---------------------------------------------------------------


def _managed_roles(connection, tenant_id: str, user_ref: str) -> set[str]:
    rows = connection.execute(
        "SELECT role FROM scim_managed_roles WHERE tenant_id = ? AND user_ref = ?", (tenant_id, user_ref)
    ).fetchall()
    return {row["role"] for row in rows}


def _active_org_admin_count(tenant_id: str) -> int:
    return sum(
        1
        for assignment in list_role_assignments(tenant_id=tenant_id)
        if assignment.get("role") == ORG_ADMIN and assignment.get("status") == "active"
    )


def reconcile_user_roles(
    tenant_id: str, user_ref: str, *, actor_ref: str = "scim", group_names: list[str] | None = None
) -> dict[str, Any]:
    """Bring the user's group-granted roles in line with their current groups.

    ``group_names`` overrides the stored SCIM membership (used for OIDC
    ``groups`` claims, which are authoritative at sign-in time).
    """
    names = group_names if group_names is not None else [g["display_name"] for g in user_groups(tenant_id, user_ref)]
    desired = _mapped_roles_for_groups(tenant_id, names)

    active_now = {
        a["role"] for a in list_role_assignments(tenant_id=tenant_id) if a.get("user_ref") == user_ref and a.get("status") == "active"
    }
    with connect() as connection:
        managed = _managed_roles(connection, tenant_id, user_ref)
    manual = active_now - managed

    # Separation of duties, fail closed: if the desired group roles (together
    # with manually held roles) would mix administration and decision
    # authority, grant neither side from the groups and log the conflict.
    combined = desired | manual
    if combined & ADMINISTRATION_ROLES and combined & DECISION_ROLES:
        conflicting = desired & (ADMINISTRATION_ROLES | DECISION_ROLES)
        record_audit(
            actor_ref=actor_ref,
            action="scim.group.role_conflict",
            tenant_id=tenant_id,
            target_type="user",
            target_id=user_ref,
            detail={"groups": names, "desired": sorted(desired), "manual": sorted(manual), "skipped": sorted(conflicting)},
        )
        desired = desired - conflicting

    granted, revoked, protected = [], [], []
    for role in sorted(desired - managed):
        if role in manual:
            # Already held by hand; record nothing so a later group removal
            # does not revoke an administrator's deliberate grant.
            continue
        upsert_role_assignment(
            {"user_ref": user_ref, "role": role, "status": "active", "tenant_id": tenant_id, "project": None, "environment": None}
        )
        with connect() as connection:
            connection.execute(
                "INSERT INTO scim_managed_roles (tenant_id, user_ref, role, granted_at) VALUES (?, ?, ?, datetime('now')) "
                "ON CONFLICT(tenant_id, user_ref, role) DO NOTHING",
                (tenant_id, user_ref, role),
            )
        granted.append(role)
    for role in sorted(managed - desired):
        if role == ORG_ADMIN and role in active_now and _active_org_admin_count(tenant_id) <= 1:
            protected.append(role)
            record_audit(
                actor_ref=actor_ref,
                action="scim.group.last_admin_protected",
                tenant_id=tenant_id,
                target_type="user",
                target_id=user_ref,
                detail={"groups": names},
            )
            continue
        upsert_role_assignment(
            {"user_ref": user_ref, "role": role, "status": "revoked", "tenant_id": tenant_id, "project": None, "environment": None}
        )
        with connect() as connection:
            connection.execute(
                "DELETE FROM scim_managed_roles WHERE tenant_id = ? AND user_ref = ? AND role = ?", (tenant_id, user_ref, role)
            )
        revoked.append(role)
    if granted or revoked:
        record_audit(
            actor_ref=actor_ref,
            action="scim.group.roles_reconciled",
            tenant_id=tenant_id,
            target_type="user",
            target_id=user_ref,
            detail={"groups": names, "granted": granted, "revoked": revoked},
        )
    return {"granted": granted, "revoked": revoked, "protected": protected}

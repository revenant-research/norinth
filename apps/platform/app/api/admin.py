from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import ActorContext, current_actor
from app.schemas.events import ScopeFilter
from app.services.auth import hash_password
from app.services.authorization import (
    ORG_ADMIN,
    PERM_ROLE_ASSIGN,
    PERM_USER_MANAGE,
    AuthorizationError,
    require_permission,
    require_super_admin,
    would_violate_role_separation,
)
from app.services.governance import build_summary
from app.storage.audit import list_audit_logs, record_audit, verify_audit_chain
from app.storage.entities import tenant_application_stats
from app.storage.organizations import (
    create_organization,
    list_organizations,
    load_organization,
    set_organization_status,
)
from app.storage.raw_events import count_events
from app.storage.retention import (
    purge_events_older_than,
    purge_tenant_data,
    tenant_data_summary,
)
from app.storage.workflow import (
    count_org_admins,
    count_platform_users,
    count_super_admins,
    count_users_pending_password,
    create_platform_user,
    get_user_by_email,
    list_all_role_permissions,
    list_permissions,
    list_platform_users,
    list_role_assignments,
    load_platform_user,
    reset_user_password,
    set_role_permission,
    set_user_status,
    tenant_user_counts,
    upsert_role_assignment,
)

router = APIRouter()


def _scrub(user: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in user.items() if key != "password_hash"}


def _temp_password() -> str:
    """A readable one-time password the admin can hand to the user. The user is
    forced to change it on first sign in."""
    return f"Norinth-{secrets.token_hex(4)}"

# Roles an org admin is allowed to grant within their organization. The platform
# role plane (super_admin) is intentionally excluded.
ASSIGNABLE_ORG_ROLES = [
    ORG_ADMIN,
    "governance_admin",
    "risk_owner",
    "control_owner",
    "governance_reviewer",
    "enterprise_subscriber",
]

# Roles a healthy governance program must keep staffed. The org admin overview
# flags any of these with no active assignee so accountability never silently
# lapses. Segregation of duties requires distinct people for owning vs reviewing.
REQUIRED_GOVERNANCE_ROLES = [
    "governance_admin",
    "risk_owner",
    "control_owner",
    "governance_reviewer",
]


class CreateOrganizationRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    admin_email: str = Field(min_length=1)
    admin_display_name: str = Field(min_length=1)
    # Optional: when omitted the platform generates a one-time password and
    # returns it once so the super admin never has to invent or relay one.
    admin_password: str | None = Field(default=None, min_length=8)


class OrganizationStatusRequest(BaseModel):
    status: str = Field(min_length=1)


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    # Optional: when omitted the platform generates a one-time password and
    # returns it once so the org admin never has to invent or relay one.
    password: str | None = Field(default=None, min_length=8)
    status: str = Field(default="active", min_length=1)


class RoleAssignmentChange(BaseModel):
    user_ref: str = Field(min_length=1)
    role: str = Field(min_length=1)
    status: str = Field(default="active", min_length=1)


class RolePermissionChange(BaseModel):
    role: str = Field(min_length=1)
    permission: str = Field(min_length=1)
    granted: bool


class AccountStatusRequest(BaseModel):
    status: str = Field(min_length=1)


def _raise_forbidden(error: AuthorizationError) -> None:
    raise HTTPException(status_code=403, detail=str(error))


def _guard_super_admin(actor: ActorContext) -> None:
    try:
        require_super_admin(actor)
    except AuthorizationError as error:
        _raise_forbidden(error)


# --- Super admin plane -------------------------------------------------------


@router.get("/api/admin/overview")
def platform_overview(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Platform-wide operational health for the super admin landing page.

    This is deliberately metadata only (counts, status, ingestion volume). It
    never reaches into any tenant's governance content, which lives on the
    tenant plane and is unreachable from the super admin."""
    _guard_super_admin(actor)
    orgs = list_organizations()
    active = sum(1 for org in orgs if org.get("status") == "active")
    return {
        "tenants": {
            "total": len(orgs),
            "active": active,
            "suspended": len(orgs) - active,
        },
        "accounts": {
            "total": count_platform_users(),
            "super_admins": count_super_admins(),
            "org_admins": count_org_admins(),
            "pending_password_reset": count_users_pending_password(),
        },
        "ingestion": {
            "events_total": count_events(),
        },
        "recent_activity": list_audit_logs(limit=8),
    }


@router.get("/api/admin/organizations")
def organizations(actor: ActorContext = Depends(current_actor)) -> dict[str, list[dict[str, Any]]]:
    _guard_super_admin(actor)
    user_counts = tenant_user_counts()
    app_stats = tenant_application_stats()
    enriched: list[dict[str, Any]] = []
    for org in list_organizations():
        tenant_id = org["tenant_id"]
        stats = app_stats.get(tenant_id, {})
        enriched.append(
            {
                **org,
                "user_count": user_counts.get(tenant_id, 0),
                "app_count": stats.get("app_count", 0),
                "last_activity": stats.get("last_activity"),
            }
        )
    return {"organizations": enriched}


@router.post("/api/admin/organizations")
def provision_organization(payload: CreateOrganizationRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    _guard_super_admin(actor)
    if get_user_by_email(payload.admin_email) is not None:
        raise HTTPException(status_code=409, detail="A user with that email already exists")
    try:
        organization = create_organization(payload.tenant_id, payload.name, actor.user_ref)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    generated_password = payload.admin_password or _temp_password()
    admin_user = create_platform_user(
        user_ref=payload.admin_email,
        display_name=payload.admin_display_name,
        email=payload.admin_email,
        password_hash=hash_password(generated_password),
        status="active",
        platform_role=None,
        tenant_id=payload.tenant_id,
        must_change_password=True,
    )
    assignment = upsert_role_assignment(
        {
            "user_ref": payload.admin_email,
            "role": ORG_ADMIN,
            "status": "active",
            "tenant_id": payload.tenant_id,
            "project": None,
            "environment": None,
        }
    )
    record_audit(
        actor_ref=actor.user_ref,
        action="org.provision",
        tenant_id=payload.tenant_id,
        target_type="organization",
        target_id=payload.tenant_id,
        detail={"name": payload.name, "org_admin": payload.admin_email},
    )
    return {
        "organization": organization,
        "org_admin": {key: value for key, value in admin_user.items() if key != "password_hash"},
        "role_assignment": assignment,
        # Only returned when the platform generated the password, so the super
        # admin can relay it once. Never returned when a password was supplied.
        "temporary_password": None if payload.admin_password else generated_password,
    }


@router.post("/api/admin/organizations/{tenant_id}/status")
def update_organization_status(tenant_id: str, payload: OrganizationStatusRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    _guard_super_admin(actor)
    if payload.status not in {"active", "suspended"}:
        raise HTTPException(status_code=400, detail="status must be 'active' or 'suspended'")
    try:
        organization = set_organization_status(tenant_id, payload.status)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="org.status",
        tenant_id=tenant_id,
        target_type="organization",
        target_id=tenant_id,
        detail={"status": payload.status},
    )
    return {"organization": organization}


class TenantPurgeRequest(BaseModel):
    # Must echo the tenant_id exactly, as a type-to-confirm safeguard against an
    # accidental irreversible deletion.
    confirm_tenant_id: str = Field(min_length=1)


class RetentionPurgeRequest(BaseModel):
    retention_days: int = Field(ge=1)


@router.get("/api/admin/organizations/{tenant_id}/data")
def tenant_data_preview(tenant_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Preview a tenant's data footprint before an irreversible erasure."""
    _guard_super_admin(actor)
    return tenant_data_summary(tenant_id)


@router.post("/api/admin/organizations/{tenant_id}/purge")
def purge_organization(
    tenant_id: str, payload: TenantPurgeRequest, actor: ActorContext = Depends(current_actor)
) -> dict[str, Any]:
    """Permanently erase all of a tenant's data (GDPR Art 17 / CCPA / BAA
    return-or-destroy). Irreversible; super admin only; requires typing the
    tenant id to confirm. The tamper-evident audit log is retained (audit H-10)."""
    _guard_super_admin(actor)
    if payload.confirm_tenant_id != tenant_id:
        raise HTTPException(status_code=400, detail="confirm_tenant_id must match the tenant being purged")
    if load_organization(tenant_id) is None:
        raise HTTPException(status_code=404, detail="organization not found")
    counts = purge_tenant_data(tenant_id)
    record_audit(
        actor_ref=actor.user_ref,
        action="org.purge",
        tenant_id=tenant_id,
        target_type="organization",
        target_id=tenant_id,
        detail={"row_counts": counts},
    )
    return {"purged": True, "tenant_id": tenant_id, "row_counts": counts}


@router.post("/api/admin/retention/purge-events")
def purge_old_events(payload: RetentionPurgeRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Age out raw SDK events older than the retention window (super admin)."""
    _guard_super_admin(actor)
    deleted = purge_events_older_than(payload.retention_days)
    record_audit(
        actor_ref=actor.user_ref,
        action="retention.purge_events",
        target_type="retention",
        target_id=str(payload.retention_days),
        detail={"deleted": deleted, "retention_days": payload.retention_days},
    )
    return {"deleted": deleted, "retention_days": payload.retention_days}


@router.get("/api/admin/users")
def all_users(actor: ActorContext = Depends(current_actor)) -> dict[str, list[dict[str, Any]]]:
    _guard_super_admin(actor)
    assignments = list_role_assignments()
    roles_by_user: dict[str, list[str]] = {}
    for assignment in assignments:
        if assignment.get("status") == "active":
            roles_by_user.setdefault(assignment["user_ref"], []).append(assignment["role"])
    users: list[dict[str, Any]] = []
    for user in list_platform_users():
        record = _scrub(user)
        record["roles"] = sorted(roles_by_user.get(user["user_ref"], []))
        users.append(record)
    return {"users": users}


@router.post("/api/admin/users/{user_ref}/status")
def update_account_status(user_ref: str, payload: AccountStatusRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Suspend or reactivate any platform account. The super admin cannot
    deactivate itself or the last remaining super admin, to avoid lockout."""
    _guard_super_admin(actor)
    if payload.status not in {"active", "suspended"}:
        raise HTTPException(status_code=400, detail="status must be 'active' or 'suspended'")
    target = load_platform_user(user_ref)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.status == "suspended" and target.get("platform_role") == "super_admin":
        if user_ref == actor.user_ref or count_super_admins() <= 1:
            raise HTTPException(status_code=400, detail="Cannot suspend the last active super admin")
    try:
        updated = set_user_status(user_ref, payload.status)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="account.status",
        tenant_id=target.get("tenant_id"),
        target_type="user",
        target_id=user_ref,
        detail={"status": payload.status},
    )
    return {"user": _scrub(updated)}


@router.post("/api/admin/users/{user_ref}/reset-password")
def reset_account_password(user_ref: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Issue a one-time temporary password. The user must change it at next sign
    in. The temporary value is returned once for the admin to deliver securely."""
    _guard_super_admin(actor)
    target = load_platform_user(user_ref)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    temp_password = _temp_password()
    reset_user_password(user_ref, hash_password(temp_password))
    record_audit(
        actor_ref=actor.user_ref,
        action="account.reset_password",
        tenant_id=target.get("tenant_id"),
        target_type="user",
        target_id=user_ref,
    )
    return {"user_ref": user_ref, "temporary_password": temp_password}


@router.get("/api/admin/role-permissions")
def role_permission_matrix(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """The platform-global role -> permission matrix, for the RBAC editor."""
    _guard_super_admin(actor)
    return {
        "roles": ASSIGNABLE_ORG_ROLES,
        "permissions": list_permissions(),
        "role_permissions": list_all_role_permissions(),
    }


@router.post("/api/admin/role-permissions")
def update_role_permission(payload: RolePermissionChange, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    # The role -> permission matrix is a platform-global default, so only the
    # super admin may edit it. Org admins assign roles, not redefine them.
    _guard_super_admin(actor)
    set_role_permission(payload.role, payload.permission, payload.granted)
    record_audit(
        actor_ref=actor.user_ref,
        action="rbac.role_permission",
        target_type="role",
        target_id=payload.role,
        detail={"permission": payload.permission, "granted": payload.granted},
    )
    return {"role": payload.role, "permission": payload.permission, "granted": payload.granted}


# --- Org admin plane ---------------------------------------------------------


def _require_tenant(actor: ActorContext) -> str:
    # The org admin plane is tenant scoped. The platform super admin is a separate
    # plane with no tenant membership, so it is denied here just as it is denied on
    # every governance data route.
    if actor.is_super_admin:
        raise HTTPException(status_code=403, detail="Platform super admins do not operate on tenant data")
    if not actor.tenant_id:
        raise HTTPException(status_code=400, detail="Actor is not bound to an organization")
    return actor.tenant_id


@router.get("/api/audit-logs")
def audit_logs(
    actor: ActorContext = Depends(current_actor),
    tenant_id: str | None = None,
    actor_ref: str | None = None,
    action: str | None = None,
    limit: int = 200,
) -> dict[str, list[dict[str, Any]]]:
    # Super admins see the full platform trail and may filter across tenants;
    # everyone else is restricted to their own organization's entries and cannot
    # widen the scope by passing a tenant_id.
    limit = max(1, min(limit, 500))
    if actor.is_super_admin:
        return {
            "audit_logs": list_audit_logs(
                tenant_id=tenant_id, actor_ref=actor_ref, action=action, limit=limit
            )
        }
    own_tenant = _require_tenant(actor)
    return {
        "audit_logs": list_audit_logs(
            tenant_id=own_tenant, actor_ref=actor_ref, action=action, limit=limit
        )
    }


@router.get("/api/admin/audit-logs/verify")
def verify_audit_logs(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Verify the integrity of the append-only audit chain (super admin only).

    Recomputes the hash chain and reports whether any entry was deleted,
    reordered, or modified (audit H-9).
    """
    _guard_super_admin(actor)
    return verify_audit_chain()


@router.get("/api/org/users")
def org_users(actor: ActorContext = Depends(current_actor)) -> dict[str, list[dict[str, Any]]]:
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    assignments = list_role_assignments(tenant_id=tenant_id)
    roles_by_user: dict[str, list[str]] = {}
    for assignment in assignments:
        if assignment.get("status") == "active":
            roles_by_user.setdefault(assignment["user_ref"], []).append(assignment["role"])
    users: list[dict[str, Any]] = []
    for user in list_platform_users(tenant_id=tenant_id):
        record = _scrub(user)
        record["roles"] = sorted(roles_by_user.get(user["user_ref"], []))
        users.append(record)
    return {"users": users}


@router.post("/api/org/users")
def create_org_user(payload: CreateUserRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    if get_user_by_email(payload.email) is not None:
        raise HTTPException(status_code=409, detail="A user with that email already exists")
    generated_password = payload.password or _temp_password()
    user = create_platform_user(
        user_ref=payload.email,
        display_name=payload.display_name,
        email=payload.email,
        password_hash=hash_password(generated_password),
        status=payload.status,
        platform_role=None,
        tenant_id=tenant_id,
        must_change_password=True,
    )
    record_audit(
        actor_ref=actor.user_ref,
        action="user.create",
        tenant_id=tenant_id,
        target_type="user",
        target_id=payload.email,
    )
    return {
        "user": {key: value for key, value in user.items() if key != "password_hash"},
        # Only returned when the platform generated the password.
        "temporary_password": None if payload.password else generated_password,
    }


@router.post("/api/org/users/{user_ref}/status")
def update_org_user_status(user_ref: str, payload: AccountStatusRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Deactivate or reactivate a user inside the admin's own organization."""
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    if payload.status not in {"active", "suspended"}:
        raise HTTPException(status_code=400, detail="status must be 'active' or 'suspended'")
    target = load_platform_user(user_ref)
    if target is None or target.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=404, detail="User not found in this organization")
    if user_ref == actor.user_ref:
        raise HTTPException(status_code=400, detail="You cannot change your own account status")
    updated = set_user_status(user_ref, payload.status)
    record_audit(
        actor_ref=actor.user_ref,
        action="user.status",
        tenant_id=tenant_id,
        target_type="user",
        target_id=user_ref,
        detail={"status": payload.status},
    )
    return {"user": _scrub(updated)}


@router.post("/api/org/users/{user_ref}/reset-password")
def reset_org_user_password(user_ref: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Issue a one-time temporary password for a user in the admin's organization."""
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    target = load_platform_user(user_ref)
    if target is None or target.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=404, detail="User not found in this organization")
    temp_password = _temp_password()
    reset_user_password(user_ref, hash_password(temp_password))
    record_audit(
        actor_ref=actor.user_ref,
        action="user.reset_password",
        tenant_id=tenant_id,
        target_type="user",
        target_id=user_ref,
    )
    return {"user_ref": user_ref, "temporary_password": temp_password}


@router.get("/api/org/overview")
def org_overview(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """Tenant posture and accountability staffing for the org admin landing page.

    Posture metrics come from the same governance services the workspace uses, so
    the org admin sees the real program state, not a separate copy. Staffing flags
    any required governance role with no active assignee."""
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    summary = build_summary(ScopeFilter(tenant_id=tenant_id))
    assignments = list_role_assignments(tenant_id=tenant_id)
    holders_by_role: dict[str, set[str]] = {}
    for assignment in assignments:
        if assignment.get("status") == "active":
            holders_by_role.setdefault(assignment["role"], set()).add(assignment["user_ref"])
    staffing = [
        {
            "role": role,
            "assignee_count": len(holders_by_role.get(role, set())),
            "staffed": len(holders_by_role.get(role, set())) > 0,
        }
        for role in REQUIRED_GOVERNANCE_ROLES
    ]
    # Segregation of duties signal: the same person owning and reviewing risk
    # collapses the maker-checker boundary, so surface that overlap explicitly.
    risk_owners = holders_by_role.get("risk_owner", set())
    reviewers = holders_by_role.get("governance_reviewer", set())
    sod_conflicts = sorted(risk_owners & reviewers)
    return {
        "tenant_id": tenant_id,
        "posture": summary,
        "staffing": staffing,
        "unstaffed_roles": [item["role"] for item in staffing if not item["staffed"]],
        "sod_conflicts": sod_conflicts,
    }


@router.get("/api/org/role-assignments")
def org_role_assignments(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_ROLE_ASSIGN, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    return {
        "role_assignments": list_role_assignments(tenant_id=tenant_id),
        "assignable_roles": ASSIGNABLE_ORG_ROLES,
        "permissions": list_permissions(),
        "role_permissions": list_all_role_permissions(),
    }


@router.post("/api/org/role-assignments")
def change_org_role_assignment(payload: RoleAssignmentChange, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    try:
        require_permission(actor, PERM_ROLE_ASSIGN, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    if payload.role not in ASSIGNABLE_ORG_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {ASSIGNABLE_ORG_ROLES}")
    # Separation of duties: an administrator must not grant or revoke their own
    # roles (no unilateral self-escalation to governance-decision authority).
    if payload.user_ref == actor.user_ref:
        raise HTTPException(
            status_code=403,
            detail="Segregation of duties: you cannot change your own role assignments; "
            "another administrator must do so",
        )
    target_user = load_platform_user(payload.user_ref)
    if target_user is None or target_user.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=404, detail="User not found in this organization")
    # A single user must not hold both an administration role and a
    # governance-decision role (audit C-4).
    existing_roles = {
        assignment["role"]
        for assignment in list_role_assignments(tenant_id=tenant_id)
        if assignment.get("user_ref") == payload.user_ref and assignment.get("status") == "active"
    }
    if would_violate_role_separation(existing_roles, payload.role, payload.status):
        raise HTTPException(
            status_code=409,
            detail="Segregation of duties: a user cannot hold both an administration role "
            "(org_admin) and a governance-decision role (e.g. governance_admin, risk_owner). "
            "Assign these to different people.",
        )
    assignment = upsert_role_assignment(
        {
            "user_ref": payload.user_ref,
            "role": payload.role,
            "status": payload.status,
            "tenant_id": tenant_id,
            "project": None,
            "environment": None,
        }
    )
    record_audit(
        actor_ref=actor.user_ref,
        action="role.assign",
        tenant_id=tenant_id,
        target_type="user",
        target_id=payload.user_ref,
        detail={"role": payload.role, "status": payload.status},
    )
    return {"role_assignment": assignment}

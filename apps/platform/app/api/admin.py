from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.pagination import PageParams
from app.dependencies import ActorContext, current_actor
from app.schemas.events import ScopeFilter
from app.services.auth import MIN_PASSWORD_LENGTH, end_all_sessions, hash_password
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
from app.services.notifications import emit as notify
from app.services.notifications import public_base_url, smtp_configured
from app.storage.audit import count_audit_logs, list_audit_logs, record_audit, verify_audit_chain
from app.storage.entities import tenant_application_stats
from app.storage.migrations import schema_status
from app.storage.notifications import INVITE_TTL_DAYS, create_invite
from app.storage.organizations import (
    create_organization,
    list_organizations,
    load_organization,
    set_organization_status,
)
from app.storage.raw_events import connect, count_events
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
    """one-time password, user must reset on first sign in"""
    return f"Norinth-{secrets.token_hex(12)}"

# roles an org admin may grant; super_admin excluded (platform plane)
ASSIGNABLE_ORG_ROLES = [
    ORG_ADMIN,
    "governance_admin",
    "risk_owner",
    "control_owner",
    "governance_reviewer",
    "governance_viewer",
]

# governance roles that must stay staffed; overview flags any with no active assignee
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
    # when omitted a one-time password is generated and returned once
    admin_password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH)


class OrganizationStatusRequest(BaseModel):
    status: str = Field(min_length=1)


class CreateUserRequest(BaseModel):
    email: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    # when omitted a one-time password is generated and returned once
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH)
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
    """super admin health overview; metadata only, no tenant content"""
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
        # only returned when we generated the password
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
    # must echo tenant_id exactly; type-to-confirm guard against accidental delete
    confirm_tenant_id: str = Field(min_length=1)


class RetentionPurgeRequest(BaseModel):
    retention_days: int = Field(ge=1)
    tenant_id: str | None = None
    # deleting across every organization at once has to be asked for
    all_tenants: bool = False


@router.get("/api/admin/organizations/{tenant_id}/data")
def tenant_data_preview(tenant_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """preview a tenant's data footprint before erasure"""
    _guard_super_admin(actor)
    # an operator looking at a tenant's footprint is visible to that tenant
    record_audit(
        actor_ref=actor.user_ref,
        action="access.tenant_data_preview",
        tenant_id=tenant_id,
        target_type="organization",
        target_id=tenant_id,
    )
    return tenant_data_summary(tenant_id)


@router.post("/api/admin/organizations/{tenant_id}/purge")
def purge_organization(
    tenant_id: str, payload: TenantPurgeRequest, actor: ActorContext = Depends(current_actor)
) -> dict[str, Any]:
    """permanently erase all tenant data; irreversible; audit log retained"""
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
    """age out raw events older than a retention window, one-off

    organizations normally set their own window (POST /api/retention-policy) and
    the maintenance worker applies it. this is the operator's manual equivalent,
    and the scope has to be stated: deleting across every organization at once
    is not something to arrive at by leaving a field out
    """
    _guard_super_admin(actor)
    if bool(payload.tenant_id) == payload.all_tenants:
        raise HTTPException(
            status_code=400,
            detail="specify tenant_id, or set all_tenants true to age out every organization",
        )
    deleted = purge_events_older_than(payload.retention_days, tenant_id=payload.tenant_id)
    record_audit(
        actor_ref=actor.user_ref,
        action="retention.purge_events",
        tenant_id=payload.tenant_id,
        target_type="retention",
        target_id=str(payload.retention_days),
        detail={
            "deleted": deleted,
            "retention_days": payload.retention_days,
            "scope": payload.tenant_id or "all_tenants",
        },
    )
    return {"deleted": deleted, "retention_days": payload.retention_days,
            "scope": payload.tenant_id or "all_tenants"}


@router.get("/api/admin/schema")
def schema(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """db backend and migration status"""
    _guard_super_admin(actor)
    return schema_status()


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
    """suspend or reactivate an account; cannot lock out the last super admin"""
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
    """issue a one-time password, returned once"""
    _guard_super_admin(actor)
    target = load_platform_user(user_ref)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    temp_password = _temp_password()
    reset_user_password(user_ref, hash_password(temp_password))
    # a reset is a clean break: drop the target's live sessions so an existing
    # login cannot continue past the reset
    end_all_sessions(user_ref)
    record_audit(
        actor_ref=actor.user_ref,
        action="account.reset_password",
        tenant_id=target.get("tenant_id"),
        target_type="user",
        target_id=user_ref,
    )
    # the platform operator is otherwise walled out of tenant data, so a reset of
    # one of an organization's own users is made visible to that organization
    # rather than being a silent way to take over an account
    tenant_id = target.get("tenant_id")
    if tenant_id:
        with connect() as connection:
            notify(
                connection,
                tenant_id=tenant_id,
                event_type="account.reset_by_operator",
                subject=f"A platform operator reset the password for {user_ref}",
                text=(
                    f"A platform operator ({actor.user_ref}) issued a one-time password reset for "
                    f"{user_ref} in your organization. If this was not expected, review the account "
                    f"and rotate its credentials."
                ),
                data={"user_ref": user_ref, "reset_by": actor.user_ref},
                to_roles=["org_admin"],
                link=f"{public_base_url()}/#users",
            )
    return {"user_ref": user_ref, "temporary_password": temp_password}


@router.get("/api/admin/role-permissions")
def role_permission_matrix(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """role -> permission matrix for the rbac editor"""
    _guard_super_admin(actor)
    return {
        "roles": ASSIGNABLE_ORG_ROLES,
        "permissions": list_permissions(),
        "role_permissions": list_all_role_permissions(),
    }


@router.post("/api/admin/role-permissions")
def update_role_permission(payload: RolePermissionChange, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    # matrix is a platform-global default; only super admin edits it
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
    # org admin plane is tenant-scoped; super admin has no tenant, denied here
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
    page: PageParams = Depends(),
) -> dict[str, Any]:
    # super admins see all tenants; everyone else pinned to own org
    effective_tenant = tenant_id if actor.is_super_admin else _require_tenant(actor)
    filters = {"tenant_id": effective_tenant, "actor_ref": actor_ref, "action": action}
    # reading the audit trail is itself an access event. recorded only on the
    # first page: one row per view session, and paging deeper must not insert
    # rows that shift the very pages being read out from under the reader
    if page.offset == 0:
        record_audit(
            actor_ref=actor.user_ref,
            action="access.audit_logs",
            tenant_id=effective_tenant,
            detail={"actor_ref": actor_ref, "action": action},
        )
    entries = list_audit_logs(**filters, limit=page.limit, offset=page.offset)
    total = count_audit_logs(**filters)
    return {
        "audit_logs": entries,
        "page": {
            "offset": page.offset,
            "limit": page.limit,
            "total": total,
            "has_more": page.offset + len(entries) < total,
        },
    }


@router.get("/api/admin/audit-logs/verify")
def verify_audit_logs(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """verify the append-only audit hash chain"""
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
    if payload.status not in {"active", "suspended"}:
        raise HTTPException(status_code=400, detail="status must be 'active' or 'suspended'")
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
    # invite link: user sets own password; emailed if smtp, else returned to admin
    token = create_invite(payload.email, tenant_id, actor.user_ref)
    invite_url = f"{public_base_url()}/#invite/{token}"
    organization = load_organization(tenant_id) or {}
    with connect() as connection:
        notify(
            connection,
            tenant_id=tenant_id,
            event_type="user.invited",
            subject=f"You have been invited to Norinth by {organization.get('name') or tenant_id}",
            text=(
                f"{actor.user_ref} invited you to {organization.get('name') or tenant_id}'s AI governance workspace.\n\n"
                f"Set your password and sign in with this link (valid for {INVITE_TTL_DAYS} days):"
            ),
            data={"user_ref": payload.email, "invited_by": actor.user_ref},
            to_users=[payload.email],
            link=invite_url,
        )
    return {
        "user": {key: value for key, value in user.items() if key != "password_hash"},
        # only returned when we generated the password
        "temporary_password": None if payload.password else generated_password,
        "invite_url": invite_url,
        "invite_emailed": smtp_configured(),
    }


@router.post("/api/org/users/{user_ref}/status")
def update_org_user_status(user_ref: str, payload: AccountStatusRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """deactivate or reactivate a user in the admin's org"""
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
    """issue a one-time password for a user in the admin's org"""
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
    """org overview: program metrics plus governance role staffing"""
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
    # flag when the same person owns and reviews risk (maker-checker overlap)
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
    if payload.status not in {"active", "revoked"}:
        raise HTTPException(status_code=400, detail="status must be 'active' or 'revoked'")
    # separation of duties: admin can't change own role assignments
    if payload.user_ref == actor.user_ref:
        raise HTTPException(
            status_code=403,
            detail="Segregation of duties: you cannot change your own role assignments; "
            "another administrator must do so",
        )
    target_user = load_platform_user(payload.user_ref)
    if target_user is None or target_user.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=404, detail="User not found in this organization")
    # a user must not hold both an admin role and a governance-decision role
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

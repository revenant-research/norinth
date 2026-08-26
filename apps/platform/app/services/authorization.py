from __future__ import annotations

from typing import Any

from app.dependencies import ActorContext
from app.storage.workflow import (
    list_actor_role_assignments,
    list_role_permissions,
    load_platform_user,
)

# org-plane roles, mapped to permissions in role_permissions (see workflow.py
# DEFAULT_ROLE_PERMISSIONS). decisions are made against permissions not role
# strings so new roles can be granted permissions without code changes
GOVERNANCE_ADMIN = "governance_admin"
ORG_ADMIN = "org_admin"
RISK_OWNER = "risk_owner"
CONTROL_OWNER = "control_owner"
GOVERNANCE_REVIEWER = "governance_reviewer"
# read-only, no governance permissions. least-privilege default for federated
# (jit/scim) users so authenticating at the idp never grants review.decide; an
# admin must deliberately elevate a user to a decision role
GOVERNANCE_VIEWER = "governance_viewer"

# mirrors workflow.DEFAULT_PERMISSIONS
PERM_ORG_MANAGE = "org.manage"
PERM_USER_MANAGE = "user.manage"
PERM_ROLE_ASSIGN = "role.assign"
PERM_CONFIG_WRITE = "config.write"
PERM_INTAKE_SUBMIT = "intake.submit"
PERM_OWNER_ASSIGN = "owner.assign"
PERM_REVIEW_DECIDE = "review.decide"
PERM_RISK_ACCEPT = "risk.accept"
PERM_GATE_DECIDE = "gate.decide"
PERM_INCIDENT_CLOSE = "incident.close"
PERM_LIFECYCLE_MANAGE = "lifecycle.manage"


class AuthorizationError(Exception):
    pass


def require_super_admin(actor: ActorContext) -> None:
    if not actor.is_super_admin:
        raise AuthorizationError(f"User {actor.user_ref} is not a platform super admin")


def require_active_actor(actor: ActorContext) -> None:
    user = load_platform_user(actor.user_ref)
    if user is None or user["status"] != "active":
        raise AuthorizationError(f"User {actor.user_ref} is not active")


def require_actor_scope(actor: ActorContext, target: dict[str, Any]) -> None:
    # fails closed: a tenant-bound actor may act only within its own tenant; a
    # target naming a different tenant, or naming none at all, is denied
    if actor.tenant_id and target.get("tenant_id") != actor.tenant_id:
        raise AuthorizationError("Actor tenant does not match target tenant")
    for field in ("project", "environment"):
        actor_value = getattr(actor, field)
        target_value = target.get(field)
        if actor_value and target_value and actor_value != target_value:
            raise AuthorizationError(f"Actor scope does not match target {field}")


def role_scope_matches(assignment: dict[str, Any], target: dict[str, Any]) -> bool:
    # tenant must match exactly; a null-scoped assignment is not a cross-tenant
    # wildcard or it would grant access to every tenant
    if assignment.get("tenant_id") != target.get("tenant_id"):
        return False
    for field in ("project", "environment"):
        assignment_value = assignment.get(field)
        target_value = target.get(field)
        if assignment_value is not None and assignment_value != target_value:
            return False
    return True


def actor_permissions(actor: ActorContext, target: dict[str, Any] | None = None) -> set[str]:
    """permissions an actor holds for a target scope

    union over every active role assignment whose scope matches the target. the
    super admin holds no tenant permissions, gated via ``require_super_admin``
    """
    permissions: set[str] = set()
    for assignment in list_actor_role_assignments(actor.user_ref):
        if target is not None and not role_scope_matches(assignment, target):
            continue
        permissions.update(list_role_permissions(assignment["role"]))
    return permissions


def require_permission(
    actor: ActorContext,
    permission: str,
    target: dict[str, Any] | None = None,
    *,
    adopt_missing_tenant: bool = False,
) -> None:
    require_active_actor(actor)
    target = dict(target or {})
    # only when the caller is creating a new, genuinely unscoped thing (a config
    # write with no tenant of its own) do we scope it to the actor's org. for a
    # LOADED record, a missing tenant is not adopted: it stays None and fails the
    # scope check below, so an orphaned tenant-less record can't be reached by
    # borrowing the acting tenant. fail-closed by default
    if adopt_missing_tenant and target.get("tenant_id") is None and actor.tenant_id:
        target["tenant_id"] = actor.tenant_id
    require_actor_scope(actor, target)
    if permission in actor_permissions(actor, target):
        return
    raise AuthorizationError(f"User {actor.user_ref} lacks required permission: {permission}")


def require_config_write(actor: ActorContext, payload: dict[str, Any] | None = None) -> None:
    # a config write may be unscoped (new config created in the actor's own org),
    # so a missing tenant is adopted from the actor
    require_permission(actor, PERM_CONFIG_WRITE, payload or {}, adopt_missing_tenant=True)


def require_owner_assignment(actor: ActorContext, assignment: dict[str, Any]) -> None:
    require_permission(actor, PERM_OWNER_ASSIGN, assignment)


def require_decision(actor: ActorContext, target: dict[str, Any]) -> None:
    # being the assignee does not grant a decision permission the actor lacks, or
    # review-queue auto-assignment would become a privilege-escalation path
    require_permission(actor, _decision_permission(target), target)


# separation of duties: one person must not both administer the tenant (manage
# users, assign roles) and hold decision authority (approve gates, accept risk,
# close incidents, decide reviews). enforced at role-assignment time
ADMINISTRATION_ROLES = {ORG_ADMIN}
DECISION_ROLES = {GOVERNANCE_ADMIN, RISK_OWNER, CONTROL_OWNER, GOVERNANCE_REVIEWER}


def would_violate_role_separation(existing_active_roles: set[str], role: str, status: str) -> bool:
    """true if the resulting role set gives one user both an admin and a decision role"""
    resulting = set(existing_active_roles)
    if status == "active":
        resulting.add(role)
    else:
        resulting.discard(role)
    return bool(resulting & ADMINISTRATION_ROLES) and bool(resulting & DECISION_ROLES)


def _decision_permission(target: dict[str, Any]) -> str:
    target_type = target.get("target_type")
    if target_type == "deployment_gate":
        return PERM_GATE_DECIDE
    if target_type == "incident":
        return PERM_INCIDENT_CLOSE
    if target_type == "risk_finding" or "risk" in target:
        return PERM_RISK_ACCEPT
    return PERM_REVIEW_DECIDE


def require_exception(actor: ActorContext, target: dict[str, Any]) -> None:
    require_permission(actor, PERM_RISK_ACCEPT, target)


def effective_permissions(actor: ActorContext) -> list[str]:
    """all tenant permissions a user holds across any scope, for ui gating

    the super admin has none; its ui is gated on ``is_super_admin`` instead
    """
    permissions: set[str] = set()
    for assignment in list_actor_role_assignments(actor.user_ref):
        permissions.update(list_role_permissions(assignment["role"]))
    return sorted(permissions)

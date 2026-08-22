from __future__ import annotations

from typing import Any

from app.dependencies import PLATFORM_SUPER_ADMIN, ActorContext
from app.storage.workflow import (
    list_actor_role_assignments,
    list_role_permissions,
    load_platform_user,
)

# Org-plane roles. These map to permissions in role_permissions (see workflow.py
# DEFAULT_ROLE_PERMISSIONS). Authorization decisions are made against permissions,
# not against role strings, so new roles can be granted permissions without code
# changes.
GOVERNANCE_ADMIN = "governance_admin"
OWNER_ADMIN = "owner_admin"
ORG_ADMIN = "org_admin"
RISK_OWNER = "risk_owner"
CONTROL_OWNER = "control_owner"
GOVERNANCE_REVIEWER = "governance_reviewer"
ENTERPRISE_SUBSCRIBER = "enterprise_subscriber"

# Permission identifiers (mirrors workflow.DEFAULT_PERMISSIONS).
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
PERM_NETWORK_READ = "network.read"


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
    for field in ("tenant_id", "project", "environment"):
        actor_value = getattr(actor, field)
        target_value = target.get(field)
        if actor_value and target_value and actor_value != target_value:
            raise AuthorizationError(f"Actor scope does not match target {field}")


def role_scope_matches(assignment: dict[str, Any], target: dict[str, Any]) -> bool:
    for field in ("tenant_id", "project", "environment"):
        assignment_value = assignment.get(field)
        target_value = target.get(field)
        if assignment_value is not None and assignment_value != target_value:
            return False
    return True


def actor_permissions(actor: ActorContext, target: dict[str, Any] | None = None) -> set[str]:
    """Resolve the set of permissions an actor holds for a target scope.

    Permissions are the union of the permissions granted to every active role
    assignment whose scope matches the target. The platform super admin is a
    separate plane: it holds no tenant governance permissions and is authorized
    only on the platform-administration endpoints via ``require_super_admin``.
    """
    permissions: set[str] = set()
    for assignment in list_actor_role_assignments(actor.user_ref):
        if target is not None and not role_scope_matches(assignment, target):
            continue
        permissions.update(list_role_permissions(assignment["role"]))
    return permissions


def require_permission(actor: ActorContext, permission: str, target: dict[str, Any] | None = None) -> None:
    require_active_actor(actor)
    target = dict(target or {})
    # A target that does not name a tenant is implicitly scoped to the actor's
    # own organization, so tenant-scoped role assignments apply to it.
    if target.get("tenant_id") is None and actor.tenant_id:
        target["tenant_id"] = actor.tenant_id
    require_actor_scope(actor, target)
    if permission in actor_permissions(actor, target):
        return
    raise AuthorizationError(f"User {actor.user_ref} lacks required permission: {permission}")


def require_config_write(actor: ActorContext, payload: dict[str, Any] | None = None) -> None:
    require_permission(actor, PERM_CONFIG_WRITE, payload or {})


def require_owner_assignment(actor: ActorContext, assignment: dict[str, Any]) -> None:
    require_permission(actor, PERM_OWNER_ASSIGN, assignment)


def require_decision(actor: ActorContext, target: dict[str, Any]) -> None:
    # The assignee of a task may always act on their own task within scope.
    if target.get("assigned_to") == actor.user_ref:
        require_active_actor(actor)
        require_actor_scope(actor, target)
        return
    permission = _decision_permission(target)
    require_permission(actor, permission, target)


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
    """All tenant permissions a user holds across any scope, for UI gating.

    The platform super admin has no tenant permissions; its UI is the
    platform-administration console, gated on ``is_super_admin`` instead.
    """
    permissions: set[str] = set()
    for assignment in list_actor_role_assignments(actor.user_ref):
        permissions.update(list_role_permissions(assignment["role"]))
    return sorted(permissions)

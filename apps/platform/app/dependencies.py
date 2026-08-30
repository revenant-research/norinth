# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Cookie, Depends, Header, HTTPException, Request

from app.schemas.events import ScopeFilter
from app.services.auth import resolve_session
from app.storage.workflow import load_platform_user

# what a user who must still enroll a second factor may reach: their own
# state, the enrollment endpoints, a password change, and the way out
_MFA_ENROLLMENT_PREFIX = "/api/auth/mfa"
_MFA_EXEMPT_PATHS = {"/api/auth/me", "/api/auth/logout", "/api/auth/change-password"}

# defined here not in authorization.py so both the dependency layer and the
# authorization service can reference it without a circular import
PLATFORM_SUPER_ADMIN = "super_admin"

SESSION_COOKIE = "norinth_session"


@dataclass(frozen=True)
class ActorContext:
    user_ref: str
    tenant_id: str | None = None
    project: str | None = None
    environment: str | None = None
    platform_role: str | None = None

    @property
    def is_super_admin(self) -> bool:
        return self.platform_role == PLATFORM_SUPER_ADMIN


def now() -> str:
    return datetime.now(UTC).isoformat()


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def ingestion_tenant(authorization: str | None = Header(default=None)) -> str:
    """resolve the ingestion bearer token to its bound tenant

    tenancy comes from the authenticated key, never the client-supplied payload;
    the ingestion route then checks every event in the batch belongs to it
    """
    # imported here to avoid a circular import at module load
    from app.storage.ingestion_keys import resolve_ingestion_key
    from app.storage.organizations import organization_is_suspended

    token = _extract_bearer(authorization)
    key = resolve_ingestion_key(token)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid or missing ingestion key")
    # purge deletes an org's keys; a suspended org keeps its keys but must stop
    # ingesting. the dev tenant has no org row and is not treated as suspended
    if organization_is_suspended(key["tenant_id"]):
        raise HTTPException(status_code=403, detail="Organization is suspended")
    return key["tenant_id"]


def scope_filter(tenant_id: str | None, project: str | None, environment: str | None) -> ScopeFilter:
    return ScopeFilter(tenant_id=tenant_id, project=project, environment=environment)


def mfa_enrollment_required(user: dict) -> bool:
    """true when the user's org requires mfa and this account hasn't enrolled

    applies only to accounts with a local password — sso/scim-provisioned
    accounts (empty password_hash) authenticate at the idp, where their second
    factor lives. the platform admin is tenant-less, so an org policy cannot
    bind it. checked cheapest-first so enrolled users never cost an org lookup
    """
    if not user.get("password_hash"):
        return False
    if user.get("mfa_enabled_at") and user.get("mfa_secret"):
        return False
    tenant_id = user.get("tenant_id")
    if not tenant_id:
        return False
    from app.storage.organizations import organization_requires_mfa

    return organization_requires_mfa(tenant_id)


def current_actor(request: Request, norinth_session: str | None = Cookie(default=None)) -> ActorContext:
    """resolve the session cookie into an ActorContext

    tenant membership comes from the stored user record, never a client header,
    so a user cannot impersonate another tenant
    """
    user_ref = resolve_session(norinth_session)
    if not user_ref:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = load_platform_user(user_ref)
    if user is None or user.get("status") != "active":
        raise HTTPException(status_code=403, detail="User is not active")
    # a suspended org freezes its users; super admins have no tenant to suspend
    tenant_id = user.get("tenant_id")
    if user.get("platform_role") != "super_admin" and tenant_id:
        from app.storage.organizations import organization_is_suspended

        if organization_is_suspended(tenant_id):
            raise HTTPException(status_code=403, detail="Organization is suspended")
    # org mfa policy: password login stays possible (enrollment is self-serve,
    # so flipping the flag can never lock an org out), but until a second
    # factor is active the session reaches only the enrollment surface
    if mfa_enrollment_required(user):
        path = request.url.path
        if path not in _MFA_EXEMPT_PATHS and not path.startswith(_MFA_ENROLLMENT_PREFIX):
            raise HTTPException(
                status_code=403,
                detail="This organization requires multi-factor authentication; enroll under Security to continue",
            )
    return ActorContext(
        user_ref=user_ref,
        tenant_id=tenant_id,
        platform_role=user.get("platform_role"),
    )


def request_scope(
    actor: ActorContext,
    project: str | None,
    environment: str | None,
) -> ScopeFilter:
    """resolve the effective query scope for an actor

    the platform super admin belongs to no tenant and gets no governance data; a
    tenant actor is pinned to their own org regardless of any requested tenant
    """
    if actor.is_super_admin:
        raise HTTPException(
            status_code=403,
            detail="Platform super admins do not have access to tenant governance data",
        )
    if not actor.tenant_id:
        raise HTTPException(status_code=403, detail="User is not bound to an organization")
    return ScopeFilter(tenant_id=actor.tenant_id, project=project, environment=environment)


def scoped_dependency(
    actor: ActorContext = Depends(current_actor),
    project: str | None = None,
    environment: str | None = None,
) -> ScopeFilter:
    """tenant-enforced scope for read routes"""
    return request_scope(actor, project, environment)

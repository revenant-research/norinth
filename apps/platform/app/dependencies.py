from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Cookie, Depends, Header, HTTPException

from app.schemas.events import ScopeFilter
from app.services.auth import resolve_session
from app.storage.workflow import load_platform_user

# Platform-plane role. Defined here (not in authorization.py) so that both the
# dependency layer and the authorization service can reference it without a
# circular import.
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
    """Resolve the ingestion Bearer token to its bound tenant.

    Telemetry tenancy is derived from the authenticated key, never from the
    client-supplied event payload. An invalid or revoked key is rejected. This
    is the authentication half of; the ingestion route then
    enforces that every event in the batch belongs to this tenant.
    """
    # Imported here to avoid a circular import at module load.
    from app.storage.ingestion_keys import resolve_ingestion_key

    token = _extract_bearer(authorization)
    key = resolve_ingestion_key(token)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid or missing ingestion key")
    return key["tenant_id"]


def scope_filter(tenant_id: str | None, project: str | None, environment: str | None) -> ScopeFilter:
    return ScopeFilter(tenant_id=tenant_id, project=project, environment=environment)


def current_actor(norinth_session: str | None = Cookie(default=None)) -> ActorContext:
    """Resolve the authenticated session cookie into an ActorContext.

    Tenant membership is derived from the stored user record, never from a
    client-supplied header, so a user cannot impersonate another tenant.
    """
    user_ref = resolve_session(norinth_session)
    if not user_ref:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = load_platform_user(user_ref)
    if user is None or user.get("status") != "active":
        raise HTTPException(status_code=403, detail="User is not active")
    return ActorContext(
        user_ref=user_ref,
        tenant_id=user.get("tenant_id"),
        platform_role=user.get("platform_role"),
    )


def request_scope(
    actor: ActorContext,
    project: str | None,
    environment: str | None,
) -> ScopeFilter:
    """Resolve the effective query scope for an actor.

    Tenant governance data belongs to the tenant plane. The platform super admin
    is not a member of any tenant and has no access to governance data; it
    operates on organizations and the platform audit trail instead. Every tenant
    actor is pinned to their own organization regardless of any requested tenant.
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
    """FastAPI dependency that yields the tenant-enforced scope for read routes."""
    return request_scope(actor, project, environment)

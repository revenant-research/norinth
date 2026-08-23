from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.dependencies import SESSION_COOKIE, ActorContext, current_actor
from app.schemas.auth import ChangePasswordRequest, LoginRequest
from app.services.auth import (
    SESSION_TTL_HOURS,
    create_session,
    end_all_sessions,
    end_session,
    hash_password,
    verify_password,
)
from app.services.authorization import effective_permissions
from app.services.bootstrap import using_development_defaults
from app.storage.audit import record_audit
from app.storage.login_attempts import clear_attempts, email_subject, ip_subject, is_locked, register_failure
from app.storage.notifications import consume_invite, peek_invite
from app.storage.organizations import load_organization
from app.storage.workflow import (
    get_user_by_email,
    load_platform_user,
    set_user_password,
)

router = APIRouter()


def _cookie_secure() -> bool:
    """Whether to mark the session cookie Secure (HTTPS-only).

    Explicit ``NORINTH_COOKIE_SECURE`` wins. Otherwise the cookie is Secure in
    production (env-configured deployments) and relaxed in local development
    (documented dev defaults, plain HTTP), so the quickstart works out of the
    box while production is protected (audit H-7).
    """
    override = os.getenv("NORINTH_COOKIE_SECURE")
    if override is not None:
        return override.lower() not in {"0", "false", "no"}
    return not using_development_defaults()


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )


def _actor_profile(actor: ActorContext) -> dict[str, Any]:
    user = load_platform_user(actor.user_ref) or {}
    return {
        "user_ref": actor.user_ref,
        "display_name": user.get("display_name", actor.user_ref),
        "email": user.get("email"),
        "tenant_id": actor.tenant_id,
        "platform_role": actor.platform_role,
        "must_change_password": bool(user.get("must_change_password")),
        "permissions": effective_permissions(actor),
        "is_super_admin": actor.is_super_admin,
    }


def client_ip(request: Request) -> str | None:
    """Source address for throttling. X-Forwarded-For is honoured only when the
    deployment declares a trusted proxy (NORINTH_TRUST_PROXY=1); otherwise a
    client could spoof the header to dodge the IP throttle."""
    if os.getenv("NORINTH_TRUST_PROXY", "0").lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    # Throttle credential stuffing / password spraying per account AND per
    # source IP (audit H-6 + follow-up: targeted-lockout DoS and cross-account
    # spraying).
    account = email_subject(payload.email)
    source = ip_subject(client_ip(request))
    if is_locked(account) or is_locked(source):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
        )
    user = get_user_by_email(payload.email)
    if user is None or user.get("status") != "active" or not verify_password(payload.password, user.get("password_hash")):
        register_failure(account)
        register_failure(source)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    clear_attempts(account)
    token = create_session(user["user_ref"])
    _set_session_cookie(response, token)
    record_audit(actor_ref=user["user_ref"], action="auth.login", tenant_id=user.get("tenant_id"))
    actor = ActorContext(
        user_ref=user["user_ref"],
        tenant_id=user.get("tenant_id"),
        platform_role=user.get("platform_role"),
    )
    return {"user": _actor_profile(actor)}


@router.post("/api/auth/logout")
def logout(response: Response, norinth_session: str | None = Cookie(default=None)) -> dict[str, bool]:
    end_session(norinth_session)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/auth/me")
def me(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    return {"user": _actor_profile(actor)}


@router.post("/api/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    norinth_session: str | None = Cookie(default=None),
    actor: ActorContext = Depends(current_actor),
) -> dict[str, Any]:
    user = load_platform_user(actor.user_ref)
    if user is None or not verify_password(payload.current_password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current password")
    set_user_password(actor.user_ref, hash_password(payload.new_password))
    # Revoke every existing session for this user (defeats a stolen/leaked token
    # surviving a password change, audit H-7), then issue a fresh rotated session
    # so the current browser stays signed in.
    end_all_sessions(actor.user_ref)
    token = create_session(actor.user_ref)
    _set_session_cookie(response, token)
    record_audit(actor_ref=actor.user_ref, action="auth.change_password", tenant_id=actor.tenant_id)
    return {"ok": True, "must_change_password": False}


@router.get("/api/auth/invite/{token}")
def invite_preview(token: str) -> dict[str, Any]:
    """What the invite page shows before the user sets a password."""
    invite = peek_invite(token)
    if invite is None:
        raise HTTPException(status_code=404, detail="This invite link is invalid, expired, or already used")
    user = load_platform_user(invite["user_ref"]) or {}
    organization = load_organization(invite["tenant_id"]) or {}
    return {"email": invite["user_ref"], "display_name": user.get("display_name"), "organization": organization.get("name") or invite["tenant_id"]}


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=12, max_length=256)


@router.post("/api/auth/accept-invite")
def accept_invite(payload: AcceptInviteRequest, response: Response) -> dict[str, Any]:
    invite = consume_invite(payload.token)
    if invite is None:
        raise HTTPException(status_code=404, detail="This invite link is invalid, expired, or already used")
    user = load_platform_user(invite["user_ref"])
    if user is None or user.get("status") != "active":
        raise HTTPException(status_code=403, detail="This account is not active")
    set_user_password(invite["user_ref"], hash_password(payload.password))  # also clears must_change_password
    end_all_sessions(invite["user_ref"])
    token = create_session(invite["user_ref"])
    _set_session_cookie(response, token)
    record_audit(actor_ref=invite["user_ref"], action="auth.accept_invite", tenant_id=invite["tenant_id"], target_type="user", target_id=invite["user_ref"])
    actor = ActorContext(user_ref=invite["user_ref"], tenant_id=invite["tenant_id"], platform_role=None)
    return {"user": _actor_profile(actor)}

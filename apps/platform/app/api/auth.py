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
    needs_rehash,
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
    upgrade_password_hash,
)

router = APIRouter()


def _cookie_secure() -> bool:
    """mark session cookie Secure; env override wins, else on outside dev"""
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
    """client ip for throttling"""
    # x-forwarded-for honored only behind a declared trusted proxy
    if os.getenv("NORINTH_TRUST_PROXY", "0").lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [part.strip() for part in forwarded.split(",") if part.strip()]
            if parts:
                # read Nth from the right; leftmost entries are client-controlled
                hops = max(1, int(os.getenv("NORINTH_TRUSTED_PROXY_HOPS", "1")))
                return parts[max(0, len(parts) - hops)]
    return request.client.host if request.client else None


@router.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    # throttle per account and per source ip
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
    # rehash if kdf params are outdated, now that we have the verified plaintext.
    # upgrade_password_hash, not set_user_password: a transparent rehash must not
    # clear must_change_password, or logging in with a temporary credential would
    # silently satisfy the forced-rotation gate
    if needs_rehash(user.get("password_hash")):
        upgrade_password_hash(user["user_ref"], hash_password(payload.password))
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
    # drop all sessions (leaked token shouldn't survive), reissue for this browser
    end_all_sessions(actor.user_ref)
    token = create_session(actor.user_ref)
    _set_session_cookie(response, token)
    record_audit(actor_ref=actor.user_ref, action="auth.change_password", tenant_id=actor.tenant_id)
    return {"ok": True, "must_change_password": False}


@router.get("/api/auth/invite/{token}")
def invite_preview(token: str) -> dict[str, Any]:
    """invite page preview before password set"""
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

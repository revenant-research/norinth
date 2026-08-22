from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response

from app.dependencies import SESSION_COOKIE, ActorContext, current_actor
from app.schemas.auth import ChangePasswordRequest, LoginRequest
from app.services.auth import (
    SESSION_TTL_HOURS,
    create_session,
    end_session,
    hash_password,
    verify_password,
)
from app.services.authorization import effective_permissions
from app.storage.audit import record_audit
from app.storage.workflow import (
    get_user_by_email,
    load_platform_user,
    set_user_password,
)

router = APIRouter()


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
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


@router.post("/api/auth/login")
def login(payload: LoginRequest, response: Response) -> dict[str, Any]:
    user = get_user_by_email(payload.email)
    if user is None or user.get("status") != "active" or not verify_password(payload.password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
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
def change_password(payload: ChangePasswordRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, bool]:
    user = load_platform_user(actor.user_ref)
    if user is None or not verify_password(payload.current_password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    set_user_password(actor.user_ref, hash_password(payload.new_password))
    record_audit(actor_ref=actor.user_ref, action="auth.change_password", tenant_id=actor.tenant_id)
    return {"ok": True}

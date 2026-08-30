# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""sso (openid connect) configuration and login endpoints"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.api.auth import _cookie_secure, _set_session_cookie
from app.dependencies import ActorContext, current_actor
from app.services.auth import create_session
from app.services.authorization import (
    PERM_USER_MANAGE,
    AuthorizationError,
    require_permission,
)
from app.services.base_url import external_base_url
from app.services.sso import SsoError, complete_login, discover, start_login
from app.storage.audit import record_audit
from app.storage.sso import (
    disable_sso_configuration,
    load_sso_configuration,
    public_sso_configuration,
    upsert_sso_configuration,
)

router = APIRouter()


class SsoConfigurationRequest(BaseModel):
    issuer: str = Field(min_length=1)
    client_id: str = Field(min_length=1)
    client_secret: str = Field(min_length=1)
    default_role: str = Field(default="governance_viewer", min_length=1)
    allowed_email_domain: str | None = None


def _require_tenant_admin(actor: ActorContext) -> str:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Organization administrator required")
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": actor.tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return actor.tenant_id


def _callback_url(request: Request) -> str:
    # public base url wins so redirect_uri matches the idp; else validate Host against allowlist
    return external_base_url(request) + "/api/auth/sso/callback"


@router.get("/api/org/sso")
def get_sso_configuration(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    return {"sso": public_sso_configuration(load_sso_configuration(tenant_id))}


@router.put("/api/org/sso")
def configure_sso(payload: SsoConfigurationRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    try:
        endpoints = discover(payload.issuer)
    except SsoError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:  # network / malformed discovery document
        raise HTTPException(
            status_code=400,
            detail=(
                "OpenID discovery failed: could not fetch "
                f"{payload.issuer.rstrip('/')}/.well-known/openid-configuration. "
                "Check that the issuer URL is correct and reachable from the platform."
            ),
        ) from error
    config = upsert_sso_configuration(
        tenant_id=tenant_id,
        issuer=endpoints["issuer"],
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        authorization_endpoint=endpoints["authorization_endpoint"],
        token_endpoint=endpoints["token_endpoint"],
        jwks_uri=endpoints["jwks_uri"],
        default_role=payload.default_role,
        allowed_email_domain=payload.allowed_email_domain,
        created_by=actor.user_ref,
    )
    record_audit(
        actor_ref=actor.user_ref,
        action="sso.configure",
        tenant_id=tenant_id,
        target_type="sso",
        target_id=tenant_id,
        detail={"issuer": endpoints["issuer"], "default_role": payload.default_role},
    )
    return {"sso": config}


@router.delete("/api/org/sso")
def remove_sso(actor: ActorContext = Depends(current_actor)) -> dict[str, bool]:
    tenant_id = _require_tenant_admin(actor)
    disable_sso_configuration(tenant_id)
    record_audit(actor_ref=actor.user_ref, action="sso.disable", tenant_id=tenant_id, target_type="sso", target_id=tenant_id)
    return {"ok": True}


# binds the oidc flow to the browser; callback is a top-level GET so SameSite=Lax
_SSO_STATE_COOKIE = "norinth_sso_state"


@router.get("/api/auth/sso/{tenant_id}/start")
def sso_start(tenant_id: str, request: Request):
    try:
        url, state = start_login(tenant_id, _callback_url(request))
    except SsoError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    redirect = RedirectResponse(url, status_code=302)
    redirect.set_cookie(
        _SSO_STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        samesite="lax",
        # same proxy-aware signal as the session cookie; behind a tls-terminating
        # proxy request.url.scheme is http, which would drop Secure on a login
        # cookie that is travelling over https
        secure=_cookie_secure(request),
        path="/api/auth/sso",
    )
    return redirect


@router.get("/api/auth/sso/callback", name="sso_callback")
def sso_callback(request: Request, response: Response, code: str | None = None, state: str | None = None):
    if not code or not state:
        raise HTTPException(status_code=400, detail="missing code or state")
    # login-csrf: idp state must match the state issued at /start
    cookie_state = request.cookies.get(_SSO_STATE_COOKIE)
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=401, detail="SSO state does not match this browser session")
    try:
        user = complete_login(code, state, _callback_url(request))
    except SsoError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    token = create_session(user["user_ref"])
    redirect = RedirectResponse("/", status_code=302)
    _set_session_cookie(request, redirect, token)
    redirect.delete_cookie(_SSO_STATE_COOKIE, path="/api/auth/sso")
    record_audit(actor_ref=user["user_ref"], action="auth.sso_login", tenant_id=user.get("tenant_id"))
    return redirect

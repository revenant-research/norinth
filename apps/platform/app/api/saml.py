"""SAML 2.0 SSO endpoints: SP metadata, login start, ACS, and org configuration."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field

from app.api.auth import _set_session_cookie
from app.dependencies import ActorContext, current_actor
from app.services.auth import create_session
from app.services.authorization import PERM_USER_MANAGE, AuthorizationError, require_permission
from app.services.saml import SamlError, acs_url, build_authn_redirect, process_response, sp_entity_id
from app.storage.audit import record_audit
from app.storage.saml import disable_saml_configuration, load_saml_configuration, upsert_saml_configuration

router = APIRouter()


class SamlConfigurationRequest(BaseModel):
    idp_entity_id: str = Field(min_length=1)
    idp_sso_url: str = Field(min_length=1)
    idp_certificate: str = Field(min_length=1, description="IdP signing certificate, PEM")
    default_role: str = Field(default="governance_viewer", min_length=1)
    allowed_email_domain: str | None = None


def _base_url(request: Request) -> str:
    return (os.getenv("NORINTH_PUBLIC_BASE_URL") or str(request.base_url)).rstrip("/")


def _require_tenant_admin(actor: ActorContext) -> str:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Organization administrator required")
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": actor.tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return actor.tenant_id


def _public(config: dict[str, Any] | None) -> dict[str, Any] | None:
    if config is None:
        return None
    # The certificate is public material; return it so the admin can confirm what's configured.
    return config


@router.get("/api/org/saml")
def get_saml(request: Request, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    base = _base_url(request)
    return {
        "saml": _public(load_saml_configuration(tenant_id)),
        "sp_entity_id": sp_entity_id(base),
        "acs_url": acs_url(base),
        "login_url": f"{base}/api/auth/saml/{tenant_id}/start",
    }


@router.put("/api/org/saml")
def configure_saml(payload: SamlConfigurationRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    cert = payload.idp_certificate.strip()
    if "BEGIN CERTIFICATE" not in cert:
        raise HTTPException(status_code=400, detail="idp_certificate must be a PEM-encoded X.509 certificate")
    config = upsert_saml_configuration(
        tenant_id=tenant_id,
        idp_entity_id=payload.idp_entity_id.strip(),
        idp_sso_url=payload.idp_sso_url.strip(),
        idp_certificate=cert,
        default_role=payload.default_role,
        allowed_email_domain=payload.allowed_email_domain,
        created_by=actor.user_ref,
    )
    record_audit(actor_ref=actor.user_ref, action="saml.configure", tenant_id=tenant_id, target_type="saml", target_id=tenant_id, detail={"idp_entity_id": payload.idp_entity_id})
    return {"saml": _public(config)}


@router.delete("/api/org/saml")
def remove_saml(actor: ActorContext = Depends(current_actor)) -> dict[str, bool]:
    tenant_id = _require_tenant_admin(actor)
    disable_saml_configuration(tenant_id)
    record_audit(actor_ref=actor.user_ref, action="saml.disable", tenant_id=tenant_id, target_type="saml", target_id=tenant_id)
    return {"ok": True}


@router.get("/api/auth/saml/metadata")
def sp_metadata(request: Request) -> Response:
    """SP metadata an IdP admin imports to set up the trust."""
    base = _base_url(request)
    xml = (
        '<?xml version="1.0"?>'
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{sp_entity_id(base)}">'
        '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs_url(base)}" index="0" isDefault="true"/>'
        "</md:SPSSODescriptor></md:EntityDescriptor>"
    )
    return Response(content=xml, media_type="application/samlmetadata+xml")


# Binds a SAML flow to the browser that started it. The ACS receives a cross-site
# POST from the IdP, so this cookie must be SameSite=None (and therefore Secure)
# to be sent — production SAML is always over https (audit finding M97).
_SAML_REQUEST_COOKIE = "norinth_saml_req"


@router.get("/api/auth/saml/{tenant_id}/start")
def saml_start(tenant_id: str, request: Request):
    try:
        url, request_id = build_authn_redirect(tenant_id, _base_url(request))
    except SamlError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    redirect = RedirectResponse(url, status_code=302)
    redirect.set_cookie(
        _SAML_REQUEST_COOKIE,
        request_id,
        max_age=600,
        httponly=True,
        samesite="none",
        secure=request.url.scheme == "https",
        path="/api/auth/saml",
    )
    return redirect


@router.post("/api/auth/saml/acs")
def saml_acs(request: Request, SAMLResponse: str = Form(...), RelayState: str | None = Form(default=None)):  # noqa: N803 - SAML field names
    expected_request_id = request.cookies.get(_SAML_REQUEST_COOKIE)
    try:
        user = process_response(SAMLResponse, _base_url(request), expected_request_id=expected_request_id)
    except SamlError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    token = create_session(user["user_ref"])
    redirect = RedirectResponse("/", status_code=303)
    _set_session_cookie(redirect, token)
    redirect.delete_cookie(_SAML_REQUEST_COOKIE, path="/api/auth/saml")
    record_audit(actor_ref=user["user_ref"], action="auth.saml_login", tenant_id=user.get("tenant_id"))
    return redirect

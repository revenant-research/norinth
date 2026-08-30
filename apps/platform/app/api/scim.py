# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""scim 2.0 user provisioning per tenant (rfc 7643/7644)"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.dependencies import ActorContext, current_actor
from app.services.auth import end_all_sessions
from app.services.authorization import (
    ADMINISTRATION_ROLES,
    PERM_USER_MANAGE,
    AuthorizationError,
    require_permission,
)
from app.storage.audit import record_audit
from app.storage.scim import (
    create_scim_token,
    list_scim_tokens,
    resolve_scim_token,
    revoke_scim_token,
    set_user_external_id,
)
from app.storage.sso import load_sso_configuration
from app.storage.workflow import (
    create_platform_user,
    list_platform_users,
    load_platform_user,
    set_user_status,
    upsert_role_assignment,
)

router = APIRouter()

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_CONTENT_TYPE = "application/scim+json"


# --- auth --------------------------------------------------------------------


def scim_tenant(authorization: str | None = Header(default=None)) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    record = resolve_scim_token(token.strip()) if scheme.lower() == "bearer" else None
    if record is None:
        raise HTTPException(status_code=401, detail="Invalid or missing SCIM token")
    return record["tenant_id"]


def _scim_error(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"schemas": [SCIM_ERROR_SCHEMA], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(status_code=status, content=body, media_type=SCIM_CONTENT_TYPE)


# --- representation ----------------------------------------------------------


def _to_scim_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": user["user_ref"],
        "externalId": user.get("external_id"),
        "userName": user.get("email") or user["user_ref"],
        "displayName": user.get("display_name"),
        "name": {"formatted": user.get("display_name")},
        "emails": [{"value": user.get("email") or user["user_ref"], "primary": True}],
        "active": user.get("status") == "active",
        "meta": {
            "resourceType": "User",
            "created": user.get("created_at"),
            "lastModified": user.get("updated_at"),
            "location": f"/scim/v2/Users/{user['user_ref']}",
        },
    }


def _load_tenant_user(user_ref: str, tenant_id: str) -> dict[str, Any] | None:
    user = load_platform_user(user_ref)
    if user is None or user.get("tenant_id") != tenant_id:
        return None
    return user


def _default_role(tenant_id: str) -> str:
    # scim users default to viewer; never auto-grant a decision role from directory presence
    config = load_sso_configuration(tenant_id)
    role = (config or {}).get("default_role") or "governance_viewer"
    return "governance_viewer" if role in ADMINISTRATION_ROLES else role


# --- ServiceProviderConfig -----------------------------------------------------


@router.get("/scim/v2/ServiceProviderConfig")
def service_provider_config(tenant_id: str = Depends(scim_tenant)):
    return JSONResponse(
        media_type=SCIM_CONTENT_TYPE,
        content={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description": "Per-tenant SCIM bearer token issued by an organization administrator",
                }
            ],
        },
    )


# --- Users -----------------------------------------------------------------------


def _parse_filter(filter_expr: str | None) -> str | None:
    """only the userName eq "x" filter idps use for reconciliation"""
    if not filter_expr:
        return None
    parts = filter_expr.strip().split(" ", 2)
    if len(parts) == 3 and parts[0].lower() in {"username", "emails.value"} and parts[1].lower() == "eq":
        return parts[2].strip().strip('"').lower()
    raise HTTPException(status_code=400, detail="unsupported filter; only 'userName eq \"value\"' is supported")


@router.get("/scim/v2/Users")
def list_users(
    tenant_id: str = Depends(scim_tenant),
    filter: str | None = None,  # noqa: A002 - SCIM parameter name
    startIndex: int = 1,  # noqa: N803 - SCIM parameter name
    count: int = 100,
):
    wanted = _parse_filter(filter)
    users = [u for u in list_platform_users(tenant_id=tenant_id) if not u.get("platform_role")]
    if wanted:
        users = [u for u in users if (u.get("email") or u["user_ref"]).lower() == wanted]
    start = max(startIndex, 1)
    page = users[start - 1 : start - 1 + max(1, min(count, 200))]
    return JSONResponse(
        media_type=SCIM_CONTENT_TYPE,
        content={
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": len(users),
            "startIndex": start,
            "itemsPerPage": len(page),
            "Resources": [_to_scim_user(u) for u in page],
        },
    )


@router.get("/scim/v2/Users/{user_ref}")
def get_user(user_ref: str, tenant_id: str = Depends(scim_tenant)):
    user = _load_tenant_user(user_ref, tenant_id)
    if user is None:
        return _scim_error(404, "User not found")
    return JSONResponse(media_type=SCIM_CONTENT_TYPE, content=_to_scim_user(user))


class ScimUserIn(BaseModel):
    userName: str = Field(min_length=1)  # noqa: N815 - SCIM attribute name
    displayName: str | None = None  # noqa: N815
    externalId: str | None = None  # noqa: N815
    active: bool = True
    name: dict[str, Any] | None = None
    emails: list[dict[str, Any]] | None = None


def _display_name(payload: ScimUserIn) -> str:
    if payload.displayName:
        return payload.displayName
    if payload.name and payload.name.get("formatted"):
        return payload.name["formatted"]
    if payload.name and (payload.name.get("givenName") or payload.name.get("familyName")):
        return " ".join(filter(None, [payload.name.get("givenName"), payload.name.get("familyName")]))
    return payload.userName


@router.post("/scim/v2/Users", status_code=201)
def create_user(payload: ScimUserIn, tenant_id: str = Depends(scim_tenant)):
    email = payload.userName.strip().lower()
    existing = load_platform_user(email)
    if existing is not None:
        if existing.get("tenant_id") != tenant_id:
            return _scim_error(409, "userName belongs to another organization", "uniqueness")
        return _scim_error(409, "User already exists", "uniqueness")
    user = create_platform_user(
        user_ref=email,
        display_name=_display_name(payload),
        email=email,
        password_hash="",  # provisioned users sign in via sso
        status="active" if payload.active else "suspended",
        platform_role=None,
        tenant_id=tenant_id,
        must_change_password=False,
    )
    if payload.externalId:
        set_user_external_id(email, payload.externalId)
        user["external_id"] = payload.externalId
    upsert_role_assignment(
        {
            "user_ref": email,
            "role": _default_role(tenant_id),
            "status": "active",
            "tenant_id": tenant_id,
            "project": None,
            "environment": None,
        }
    )
    record_audit(actor_ref="scim", action="scim.user.create", tenant_id=tenant_id, target_type="user", target_id=email)
    return JSONResponse(status_code=201, media_type=SCIM_CONTENT_TYPE, content=_to_scim_user(user))


def _apply_active(user_ref: str, tenant_id: str, active: bool) -> dict[str, Any]:
    updated = set_user_status(user_ref, "active" if active else "suspended")
    if not active:
        end_all_sessions(user_ref)  # deprovision immediately
    record_audit(
        actor_ref="scim",
        action="scim.user.activate" if active else "scim.user.deactivate",
        tenant_id=tenant_id,
        target_type="user",
        target_id=user_ref,
    )
    return updated


@router.put("/scim/v2/Users/{user_ref}")
def replace_user(user_ref: str, payload: ScimUserIn, tenant_id: str = Depends(scim_tenant)):
    user = _load_tenant_user(user_ref, tenant_id)
    if user is None:
        return _scim_error(404, "User not found")
    from app.storage.workflow import upsert_platform_user

    upsert_platform_user({"user_ref": user_ref, "display_name": _display_name(payload), "status": user["status"]})
    if payload.externalId is not None:
        set_user_external_id(user_ref, payload.externalId)
    if payload.active != (user.get("status") == "active"):
        _apply_active(user_ref, tenant_id, payload.active)
    record_audit(actor_ref="scim", action="scim.user.replace", tenant_id=tenant_id, target_type="user", target_id=user_ref)
    return JSONResponse(media_type=SCIM_CONTENT_TYPE, content=_to_scim_user(load_platform_user(user_ref) or user))


class ScimPatch(BaseModel):
    schemas: list[str] = Field(default_factory=list)
    Operations: list[dict[str, Any]] = Field(default_factory=list)  # noqa: N815 - SCIM attribute name


@router.patch("/scim/v2/Users/{user_ref}")
def patch_user(user_ref: str, payload: ScimPatch, tenant_id: str = Depends(scim_tenant)):
    user = _load_tenant_user(user_ref, tenant_id)
    if user is None:
        return _scim_error(404, "User not found")
    for operation in payload.Operations:
        op = str(operation.get("op", "")).lower()
        path = str(operation.get("path", "") or "").lower()
        value = operation.get("value")
        if op not in {"replace", "add"}:
            return _scim_error(400, f"unsupported op: {op}", "invalidValue")
        # entra/okta send {"path":"active","value":false} or bare {"value":{"active":false}}
        updates: dict[str, Any] = {}
        if path:
            updates[path] = value
        elif isinstance(value, dict):
            updates.update({k.lower(): v for k, v in value.items()})
        for key, val in updates.items():
            if key == "active":
                active = val if isinstance(val, bool) else str(val).lower() == "true"
                _apply_active(user_ref, tenant_id, active)
            elif key == "displayname":
                from app.storage.workflow import upsert_platform_user

                upsert_platform_user({"user_ref": user_ref, "display_name": str(val), "status": (load_platform_user(user_ref) or user)["status"]})
            elif key == "externalid":
                set_user_external_id(user_ref, None if val is None else str(val))
            # other attributes accepted and ignored (scim allows partial support)
    return JSONResponse(media_type=SCIM_CONTENT_TYPE, content=_to_scim_user(load_platform_user(user_ref) or user))


@router.delete("/scim/v2/Users/{user_ref}", status_code=204)
def delete_user(user_ref: str, tenant_id: str = Depends(scim_tenant)):
    user = _load_tenant_user(user_ref, tenant_id)
    if user is None:
        return _scim_error(404, "User not found")
    # deactivate not delete so audit/decision history stays intact
    _apply_active(user_ref, tenant_id, False)
    return Response(status_code=204)


# --- org-admin token management -------------------------------------------------


class ScimTokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


def _require_tenant_admin(actor: ActorContext) -> str:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Organization administrator required")
    try:
        require_permission(actor, PERM_USER_MANAGE, {"tenant_id": actor.tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return actor.tenant_id


@router.get("/api/org/scim-tokens")
def org_scim_tokens(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    return {"scim_tokens": list_scim_tokens(tenant_id), "scim_base_url": "/scim/v2"}


@router.post("/api/org/scim-tokens")
def create_org_scim_token(payload: ScimTokenRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    token, record = create_scim_token(tenant_id, payload.name, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="scim_token.create", tenant_id=tenant_id, target_type="scim_token", target_id=record["token_id"])
    return {"scim_token": record, "token": token}


@router.post("/api/org/scim-tokens/{token_id}/revoke")
def revoke_org_scim_token(token_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant_admin(actor)
    try:
        record = revoke_scim_token(token_id, tenant_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    record_audit(actor_ref=actor.user_ref, action="scim_token.revoke", tenant_id=tenant_id, target_type="scim_token", target_id=token_id)
    return {"scim_token": record}


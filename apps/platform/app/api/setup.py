# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""first-run setup wizard: create the first org and its admin"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import ActorContext, current_actor
from app.services.auth import hash_password
from app.services.authorization import ORG_ADMIN, AuthorizationError, require_super_admin
from app.storage.audit import record_audit
from app.storage.organizations import create_organization, list_organizations
from app.storage.workflow import create_platform_user, get_user_by_email, load_platform_user, upsert_role_assignment

router = APIRouter()

_SLUG = re.compile(r"[^a-z0-9]+")


def setup_needed() -> bool:
    return not list_organizations()


def slugify(name: str) -> str:
    slug = _SLUG.sub("-", name.strip().lower()).strip("-")
    return slug[:48] or "org"


class SetupOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    tenant_id: str | None = Field(default=None, max_length=64)
    admin_email: str = Field(min_length=3, max_length=254)
    admin_display_name: str = Field(min_length=1, max_length=120)
    admin_password: str = Field(min_length=12, max_length=256)


@router.get("/api/setup/state")
def setup_state() -> dict[str, Any]:
    return {"needs_setup": setup_needed()}


@router.post("/api/setup/organization", status_code=201)
def setup_organization(payload: SetupOrganizationRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    try:
        require_super_admin(actor)
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    if not setup_needed():
        raise HTTPException(status_code=409, detail="Setup is complete; create further organizations from the console")
    admin = load_platform_user(actor.user_ref) or {}
    if admin.get("must_change_password"):
        raise HTTPException(status_code=409, detail="Set your administrator password first")
    email = payload.admin_email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="enter a valid email address")
    if get_user_by_email(email) is not None:
        raise HTTPException(status_code=409, detail="A user with that email already exists")
    tenant_id = slugify(payload.tenant_id or payload.name)
    try:
        organization = create_organization(tenant_id, payload.name.strip(), actor.user_ref)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    create_platform_user(
        user_ref=email,
        display_name=payload.admin_display_name.strip(),
        email=email,
        password_hash=hash_password(payload.admin_password),
        status="active",
        platform_role=None,
        tenant_id=tenant_id,
        must_change_password=False,  # operator just chose this password
    )
    upsert_role_assignment(
        {"user_ref": email, "role": ORG_ADMIN, "status": "active", "tenant_id": tenant_id, "project": None, "environment": None}
    )
    record_audit(
        actor_ref=actor.user_ref,
        action="org.provision",
        tenant_id=tenant_id,
        target_type="organization",
        target_id=tenant_id,
        detail={"name": payload.name, "org_admin": email, "via": "setup_wizard"},
    )
    return {"organization": organization, "org_admin_email": email}

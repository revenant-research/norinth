# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""org management of per-tenant ingestion keys"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import ActorContext, current_actor
from app.schemas.workflow import IngestionKeyRequest
from app.services.authorization import (
    PERM_CONFIG_WRITE,
    AuthorizationError,
    require_permission,
)
from app.storage.audit import record_audit
from app.storage.errors import DomainError
from app.storage.ingestion_keys import (
    create_ingestion_key,
    list_ingestion_keys,
    revoke_ingestion_key,
)

router = APIRouter()


def _require_tenant(actor: ActorContext) -> str:
    if actor.is_super_admin:
        raise HTTPException(
            status_code=403,
            detail="Platform super admins do not manage tenant ingestion keys",
        )
    if not actor.tenant_id:
        raise HTTPException(status_code=403, detail="User is not bound to an organization")
    return actor.tenant_id


def _authorize(actor: ActorContext, tenant_id: str) -> None:
    try:
        require_permission(actor, PERM_CONFIG_WRITE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@router.get("/api/ingestion-keys")
def list_keys(actor: ActorContext = Depends(current_actor)) -> dict[str, list[dict[str, Any]]]:
    tenant_id = _require_tenant(actor)
    _authorize(actor, tenant_id)
    return {"ingestion_keys": list_ingestion_keys(tenant_id)}


@router.post("/api/ingestion-keys")
def create_key(payload: IngestionKeyRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    _authorize(actor, tenant_id)
    token, record = create_ingestion_key(tenant_id, payload.name, actor.user_ref)
    record_audit(
        actor_ref=actor.user_ref,
        action="ingestion_key.create",
        tenant_id=tenant_id,
        target_type="ingestion_key",
        target_id=record["key_id"],
        detail={"name": payload.name},
    )
    # plaintext token returned once, never stored
    return {"ingestion_key": record, "token": token}


@router.post("/api/ingestion-keys/{key_id}/revoke")
def revoke_key(key_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    _authorize(actor, tenant_id)
    try:
        record = revoke_ingestion_key(key_id, tenant_id)
    except DomainError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="ingestion_key.revoke",
        tenant_id=tenant_id,
        target_type="ingestion_key",
        target_id=key_id,
    )
    return {"ingestion_key": record}

"""Org-plane management of evidence attestation keys.

An organization admin registers the Ed25519 *public* key its CI pipeline uses
to sign eval results. From the first active key onward, deployment gates in
that organization only count attested passing evals. Revocation is immediate:
evidence signed by a revoked key is rejected at ingestion, and already-stored
evidence keeps its ``attested`` flag as a historical fact (the audit log shows
when the key was revoked).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import ActorContext, current_actor
from app.schemas.workflow import AttestationKeyRequest
from app.services.attestation import AttestationError, load_public_key
from app.services.authorization import PERM_CONFIG_WRITE, AuthorizationError, require_permission
from app.storage.attestation_keys import (
    create_attestation_key,
    list_attestation_keys,
    revoke_attestation_key,
)
from app.storage.audit import record_audit

router = APIRouter()


def _require_tenant(actor: ActorContext) -> str:
    if actor.is_super_admin:
        raise HTTPException(status_code=403, detail="Platform super admins do not manage tenant attestation keys")
    if not actor.tenant_id:
        raise HTTPException(status_code=403, detail="User is not bound to an organization")
    return actor.tenant_id


def _authorize(actor: ActorContext, tenant_id: str) -> None:
    try:
        require_permission(actor, PERM_CONFIG_WRITE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@router.get("/api/attestation-keys")
def list_keys(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    _authorize(actor, tenant_id)
    keys = list_attestation_keys(tenant_id)
    return {
        "attestation_keys": keys,
        "attestation_required": any(key["status"] == "active" for key in keys),
    }


@router.post("/api/attestation-keys")
def register_key(payload: AttestationKeyRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    _authorize(actor, tenant_id)
    try:
        load_public_key(payload.public_key_pem)
    except AttestationError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record = create_attestation_key(tenant_id, payload.name, payload.public_key_pem.strip(), actor.user_ref)
    record_audit(
        actor_ref=actor.user_ref,
        action="attestation_key.register",
        tenant_id=tenant_id,
        target_type="attestation_key",
        target_id=record["key_id"],
        detail={"name": payload.name, "fingerprint": record["fingerprint"]},
    )
    return {"attestation_key": record}


@router.post("/api/attestation-keys/{key_id}/revoke")
def revoke_key(key_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _require_tenant(actor)
    _authorize(actor, tenant_id)
    try:
        record = revoke_attestation_key(key_id, tenant_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="attestation_key.revoke",
        tenant_id=tenant_id,
        target_type="attestation_key",
        target_id=key_id,
    )
    return {"attestation_key": record}

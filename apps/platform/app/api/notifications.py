"""org webhooks and notification delivery log"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import ActorContext, current_actor
from app.services.authorization import PERM_CONFIG_WRITE, AuthorizationError, require_permission
from app.services.notifications import deliver_pending, emit, smtp_configured
from app.storage import notifications as store
from app.storage.audit import record_audit
from app.storage.raw_events import connect

router = APIRouter()


def _tenant(actor: ActorContext) -> str:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Webhooks belong to an organization")
    try:
        require_permission(actor, PERM_CONFIG_WRITE, {"tenant_id": actor.tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return actor.tenant_id


class WebhookRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(default_factory=lambda: ["*"])
    format: str = Field(default="json")


@router.get("/api/org/webhooks")
def list_hooks(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _tenant(actor)
    return {"webhooks": store.list_webhooks(tenant_id), "events": list(store.WEBHOOK_EVENTS), "smtp_configured": smtp_configured()}


@router.post("/api/org/webhooks", status_code=201)
def create_hook(payload: WebhookRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _tenant(actor)
    if not payload.url.lower().startswith("https://") and not payload.url.lower().startswith("http://"):
        raise HTTPException(status_code=400, detail="url must be http(s)")
    if payload.format not in {"json", "slack"}:
        raise HTTPException(status_code=400, detail="format must be 'json' or 'slack'")
    unknown = [e for e in payload.events if e != "*" and e not in store.WEBHOOK_EVENTS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown events: {unknown}")
    secret, record = store.create_webhook(tenant_id, name=payload.name, url=payload.url, events=payload.events, fmt=payload.format, created_by=actor.user_ref)
    # log only the masked host; a slack webhook path is a bearer secret
    record_audit(actor_ref=actor.user_ref, action="webhook.create", tenant_id=tenant_id, target_type="webhook", target_id=record["webhook_id"], detail={"url": store.mask_url(payload.url), "events": payload.events})
    # signing secret shown once
    return {"webhook": record, "secret": secret}


@router.delete("/api/org/webhooks/{webhook_id}", status_code=204)
def delete_hook(webhook_id: str, actor: ActorContext = Depends(current_actor)) -> None:
    tenant_id = _tenant(actor)
    if not store.delete_webhook(webhook_id, tenant_id):
        raise HTTPException(status_code=404, detail="webhook not found")
    record_audit(actor_ref=actor.user_ref, action="webhook.delete", tenant_id=tenant_id, target_type="webhook", target_id=webhook_id)


@router.post("/api/org/webhooks/{webhook_id}/test")
def test_hook(webhook_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _tenant(actor)
    hook = store.load_webhook(webhook_id, tenant_id)
    if hook is None:
        raise HTTPException(status_code=404, detail="webhook not found")
    with connect() as connection:
        store.enqueue(
            connection,
            tenant_id=tenant_id,
            channel="webhook",
            event_type="test",
            target=webhook_id,
            subject="Norinth test notification",
            payload={"type": "test", "tenant_id": tenant_id, "subject": "Norinth test notification", "text": f"Sent by {actor.user_ref} from Identity & Integrations.", "data": {}, "link": None},
        )
    result = deliver_pending(limit=20)
    refreshed = store.load_webhook(webhook_id, tenant_id) or {}
    return {"delivered": result, "last_status": refreshed.get("last_status")}


@router.get("/api/org/notifications")
def delivery_log(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _tenant(actor)
    return {"notifications": store.list_outbox(tenant_id), "smtp_configured": smtp_configured()}


__all__ = ["router", "emit"]

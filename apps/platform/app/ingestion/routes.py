from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.dependencies import ingestion_tenant
from app.ingestion.otel import otel_spans_to_events
from app.schemas.events import EventBatch
from app.storage.deployments import process_deployment_events, refresh_deployment_gates
from app.storage.entities import process_events
from app.storage.governance_policy import refresh_governance_assessments
from app.storage.incidents import process_incident_events
from app.storage.lifecycle import refresh_lifecycle_state
from app.storage.prompts import process_prompt_events
from app.storage.raw_events import count_events, insert_events
from app.storage.workflow import refresh_workflow_state

router = APIRouter()


# Attributes each event type requires beyond the envelope. The entity
# processors access these without a default, so a missing one previously crashed
# ingestion with an unhandled 500 after a partial write (audit C-6). Validation
# runs before any write, so a malformed batch is rejected atomically with 422.
_REQUIRED_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "deployment.event": ("deployment_id", "version", "artifact_ref"),
    "prompt.event": ("prompt_id", "version", "artifact_ref"),
}


def _validate_event_attributes(events: list[dict[str, Any]]) -> None:
    for index, event in enumerate(events):
        required = _REQUIRED_ATTRIBUTES.get(event.get("type", ""))
        if not required:
            continue
        attributes = event.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise HTTPException(status_code=422, detail=f"events[{index}].attributes must be an object")
        missing = [field for field in required if attributes.get(field) in (None, "")]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"events[{index}] ({event.get('type')}) is missing required attributes: {', '.join(missing)}",
            )


def _bind_events_to_tenant(events: list[dict[str, Any]], tenant_id: str) -> None:
    """Enforce that every event belongs to the authenticated tenant.

    The tenant is derived from the ingestion key (see ``ingestion_tenant``), not
    from the client payload. Events that omit a tenant are stamped with the
    authenticated tenant; events that claim a *different* tenant are rejected for
    the whole batch. This closes the cross-tenant evidence-forgery hole (C-1) and
    guarantees no NULL-tenant rows enter storage via authenticated ingestion.
    """
    for event in events:
        attributes = event.setdefault("attributes", {})
        if not isinstance(attributes, dict):
            raise HTTPException(status_code=400, detail="event.attributes must be an object")
        metadata = attributes.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            raise HTTPException(status_code=400, detail="event.attributes.metadata must be an object")
        claimed = metadata.get("tenant_id")
        if claimed is not None and claimed != tenant_id:
            raise HTTPException(
                status_code=403,
                detail="event tenant_id does not match the authenticated ingestion key",
            )
        metadata["tenant_id"] = tenant_id


@router.post("/v1/events/batch")
async def ingest_events(
    request: Request,
    batch: EventBatch,
    tenant_id: str = Depends(ingestion_tenant),
):
    signing_secret = os.getenv("NORINTH_SIGNING_SECRET")
    if signing_secret:
        signature_header = request.headers.get("X-Norinth-Signature")
        if not signature_header or not signature_header.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Missing or invalid signature")

        body = await request.body()
        expected_mac = hmac.new(signing_secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256).hexdigest()

        if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
            raise HTTPException(status_code=401, detail="Signature mismatch")

    events = [event.model_dump() for event in batch.events]
    return _ingest(events, tenant_id)


@router.post("/v1/otel/traces")
async def ingest_otel_traces(
    request: Request,
    tenant_id: str = Depends(ingestion_tenant),
):
    """Ingest OpenTelemetry GenAI spans (OTLP/HTTP JSON).

    Lets Norinth consume telemetry from any OTel-instrumented framework or LLM
    gateway, mapping gen_ai.* spans to the same event shapes the SDK emits so the
    governance pipeline processes them unchanged. Non-GenAI spans are skipped.
    """
    try:
        payload = await request.json()
    except Exception as error:
        raise HTTPException(status_code=400, detail="invalid JSON body") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="OTLP payload must be a JSON object")
    events = otel_spans_to_events(payload)
    if not events:
        return {"accepted": 0, "total": count_events(), "skipped": "no GenAI spans found"}
    return _ingest(events, tenant_id)


def _ingest(events: list[dict[str, Any]], tenant_id: str) -> dict[str, Any]:
    # Validate and bind BEFORE any write, so a malformed batch is rejected
    # atomically (422) rather than crashing mid-pipeline after a partial insert.
    _validate_event_attributes(events)
    _bind_events_to_tenant(events, tenant_id)
    accepted = insert_events(events)
    process_events(events)
    process_prompt_events(events)
    process_deployment_events(events)
    process_incident_events(events)
    refresh_lifecycle_state()
    refresh_governance_assessments()
    refresh_workflow_state()
    refresh_deployment_gates()
    return {"accepted": accepted, "total": count_events()}

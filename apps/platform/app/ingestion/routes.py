from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import APIRouter, Depends, HTTPException, Request

from app.dependencies import require_api_key
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


@router.post("/v1/events/batch")
async def ingest_events(request: Request, batch: EventBatch, _: None = Depends(require_api_key)):
    signing_secret = os.getenv("NORINTH_SIGNING_SECRET")
    if signing_secret:
        signature_header = request.headers.get("X-Norinth-Signature")
        if not signature_header or not signature_header.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Missing or invalid signature")
        
        body = await request.body()
        expected_mac = hmac.new(signing_secret.encode('utf-8'), msg=body, digestmod=hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
            raise HTTPException(status_code=401, detail="Signature mismatch")

    events = [event.model_dump() for event in batch.events]
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

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import hashlib
import hmac
import math
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.dependencies import ingestion_tenant
from app.ingestion.otel import OtelPayloadError, otel_spans_to_events
from app.schemas.events import MAX_BATCH_EVENTS, EventBatch
from app.services.attestation import AttestationError, verify_eval_attestation
from app.storage.agents import refresh_agent_posture
from app.storage.attestation_keys import load_active_attestation_key, touch_attestation_key
from app.storage.audit import record_audit
from app.storage.deployments import find_gate_for_release, process_deployment_events, refresh_deployment_gates
from app.storage.entities import process_events
from app.storage.governance_policy import fold_batch_assessments
from app.storage.incidents import process_incident_events
from app.storage.lifecycle import fold_batch_fingerprints
from app.storage.policy_engine import refresh_vendor_posture
from app.storage.prompts import process_prompt_events
from app.storage.raw_events import insert_events
from app.storage.workflow import expire_due_exceptions, refresh_workflow_state

router = APIRouter()


# attributes each event type needs; validated before any write so a bad batch is a clean 422
_REQUIRED_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "deployment.event": ("deployment_id", "version", "artifact_ref"),
    "prompt.event": ("prompt_id", "version", "artifact_ref"),
}


# attributes the pipeline reads as nested objects; reject non-object here so recompute can't choke
_OBJECT_ATTRIBUTES = ("metadata", "prompt", "response", "usage", "template", "change_notes", "description", "attestation")


# usage counters the pipeline sums into storage. int() raises TypeError on a
# list and OverflowError on 1e400, and neither is a ValueError, so both escaped
# the handler and surfaced as a 500. numeric strings still pass: clients send
# them and int() has always accepted them
_NUMERIC_USAGE_FIELDS = ("input_tokens", "output_tokens")


def _validate_usage(index: int, usage: dict[str, Any]) -> None:
    for field in _NUMERIC_USAGE_FIELDS:
        value = usage.get(field)
        if value is None or isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            if isinstance(value, float) and not math.isfinite(value):
                raise HTTPException(
                    status_code=422,
                    detail=f"events[{index}].attributes.usage.{field} must be a finite number",
                )
            continue
        if isinstance(value, str):
            try:
                parsed = float(value)
            except ValueError:
                parsed = None
            if parsed is not None and math.isfinite(parsed):
                continue
        raise HTTPException(
            status_code=422,
            detail=f"events[{index}].attributes.usage.{field} must be a number",
        )


def _validate_event_attributes(events: list[dict[str, Any]]) -> None:
    for index, event in enumerate(events):
        attributes = event.get("attributes")
        if attributes is not None and not isinstance(attributes, dict):
            raise HTTPException(status_code=422, detail=f"events[{index}].attributes must be an object")
        attributes = attributes or {}
        for key in _OBJECT_ATTRIBUTES:
            if key in attributes and attributes[key] is not None and not isinstance(attributes[key], dict):
                raise HTTPException(
                    status_code=422,
                    detail=f"events[{index}].attributes.{key} must be an object",
                )
        _validate_usage(index, attributes.get("usage") or {})
        required = _REQUIRED_ATTRIBUTES.get(event.get("type", ""))
        if not required:
            continue
        missing = [field for field in required if attributes.get(field) in (None, "")]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"events[{index}] ({event.get('type')}) is missing required attributes: {', '.join(missing)}",
            )


def _bind_events_to_tenant(events: list[dict[str, Any]], tenant_id: str) -> None:
    """pin every event to the authenticated tenant; reject events claiming another"""
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


async def _verify_optional_signature(request: Request) -> None:
    """when NORINTH_SIGNING_SECRET is set, require a valid HMAC over the raw body

    applied to every ingest entrypoint so the OTLP path is not an unsigned way in
    """
    signing_secret = os.getenv("NORINTH_SIGNING_SECRET")
    if not signing_secret:
        return
    signature_header = request.headers.get("X-Norinth-Signature")
    if not signature_header or not signature_header.startswith("sha256="):
        raise HTTPException(status_code=401, detail="Missing or invalid signature")
    body = await request.body()
    expected_mac = hmac.new(signing_secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
        raise HTTPException(status_code=401, detail="Signature mismatch")


@router.post("/v1/events/batch")
async def ingest_events(
    request: Request,
    batch: EventBatch,
    tenant_id: str = Depends(ingestion_tenant),
):
    await _verify_optional_signature(request)
    events = [event.model_dump() for event in batch.events]
    # ingest is sync db work; run off the event loop so a big recompute can't block the server
    return await run_in_threadpool(_ingest, events, tenant_id)


@router.post("/v1/otel/traces")
async def ingest_otel_traces(
    request: Request,
    tenant_id: str = Depends(ingestion_tenant),
):
    """ingest opentelemetry gen_ai spans (otlp/http json)"""
    await _verify_optional_signature(request)
    try:
        payload = await request.json()
    except Exception as error:
        raise HTTPException(status_code=400, detail="invalid JSON body") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="OTLP payload must be a JSON object")
    try:
        events = otel_spans_to_events(payload)
    except OtelPayloadError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    # the same per-request cap the native batch endpoint enforces via its schema;
    # otlp builds the event list itself, so it would otherwise be uncapped
    if len(events) > MAX_BATCH_EVENTS:
        raise HTTPException(status_code=413, detail=f"too many spans in one request; max {MAX_BATCH_EVENTS}")
    if not events:
        return {"accepted": 0, "skipped": "no GenAI spans found"}
    return await run_in_threadpool(_ingest, events, tenant_id)


def _verify_eval_attestations(events: list[dict[str, Any]], tenant_id: str) -> None:
    """set attested only after an ed25519 sig verifies against an active key; never a client claim"""
    for event in events:
        attrs = event.get("attributes")
        if not isinstance(attrs, dict):
            continue
        attrs.pop("attested", None)
        attrs.pop("attested_key_id", None)
        if event.get("type") != "eval.result":
            attrs.pop("attestation", None)
            continue
        attestation = attrs.get("attestation")
        if attestation is None:
            attrs["attested"] = False
            continue
        if not isinstance(attestation, dict):
            raise HTTPException(status_code=400, detail="attestation must be an object {key_id, signature}")
        key_id = str(attestation.get("key_id") or "")
        signature = str(attestation.get("signature") or "")
        key = load_active_attestation_key(tenant_id, key_id) if key_id else None
        try:
            if key is None:
                raise AttestationError("attestation key is unknown, revoked, or belongs to another organization")
            verify_eval_attestation(event, key["public_key_pem"], signature)
        except AttestationError as error:
            record_audit(
                actor_ref=f"ingestion:{tenant_id}",
                action="evidence.attestation_rejected",
                tenant_id=tenant_id,
                target_type="eval_result",
                target_id=f"{event.get('trace_id')}/{event.get('span_id')}",
                detail={"key_id": key_id, "reason": str(error)},
            )
            raise HTTPException(
                status_code=400,
                detail=f"eval attestation rejected for span {event.get('span_id')}: {error}",
            ) from error
        attrs["attested"] = True
        attrs["attested_key_id"] = key_id
        touch_attestation_key(key_id)


def batch_scopes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """scopes a batch touches; derived state recomputes only for these"""
    seen: dict[tuple, dict[str, Any]] = {}
    for event in events:
        metadata = (event.get("attributes") or {}).get("metadata") or {}
        application_name = metadata.get("application_name")
        if not application_name:
            continue
        scope = {
            "tenant_id": metadata.get("tenant_id"),
            "project": event.get("project"),
            "environment": event.get("environment"),
            "application_name": application_name,
        }
        seen[tuple(scope.values())] = scope
    return list(seen.values())


def _ingest(events: list[dict[str, Any]], tenant_id: str) -> dict[str, Any]:
    # validate and bind before any write so a bad batch is a clean 422, not a partial insert
    _validate_event_attributes(events)
    _bind_events_to_tenant(events, tenant_id)
    _verify_eval_attestations(events, tenant_id)
    # project only the newly inserted events; a retried batch inserts nothing, so
    # it must not re-run the increment projections and double-count metrics
    inserted = insert_events(events)
    if inserted:
        process_events(inserted)
        process_prompt_events(inserted)
        process_deployment_events(inserted)
        process_incident_events(inserted)
        # expire lapsed exceptions (reopens their findings) before recompute
        expire_due_exceptions()
        # fold the batch into derived state at O(batch): the full refresh_*
        # functions re-read (and with encryption on, decrypt) each touched
        # app's entire history, a cost that grows with every successful day.
        # they remain the rebuild path; the request path folds
        scopes = batch_scopes(inserted)
        fold_batch_fingerprints(inserted)
        fold_batch_assessments(inserted)
        refresh_agent_posture([tenant_id])
        refresh_vendor_posture([tenant_id])
        refresh_workflow_state(scopes)
        refresh_deployment_gates(scopes)
    return {"accepted": len(inserted)}


@router.get("/v1/gates/check")
def gate_check(deployment_id: str, version: str, tenant_id: str = Depends(ingestion_tenant)) -> dict[str, Any]:
    """release-gate status for ci; read-only, tenant-bound, minimal"""
    gate = find_gate_for_release(tenant_id, deployment_id, version)
    if gate is None:
        raise HTTPException(status_code=404, detail="no release gate for that deployment and version (has the deployment.event been ingested?)")
    return {
        "gate_id": gate["gate_id"],
        "deployment_id": gate["deployment_id"],
        "version": gate["version"],
        "application_name": gate["application_name"],
        "workflow_name": gate["workflow_name"],
        "status": gate["gate_status"],
        "approved": gate["gate_status"] == "approved",
        "blocking": None if gate["gate_status"] == "approved" else gate.get("required_reason"),
        "decided_by": gate.get("actor_ref"),
        "decided_at": gate.get("decided_at"),
    }

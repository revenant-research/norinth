from __future__ import annotations

from typing import Any

import norinth_logger as norinth
from fastapi import FastAPI


def configure_observability(app: FastAPI, settings: Any) -> None:
    norinth.init(
        api_key=settings.norinth_api_key,
        endpoint=settings.norinth_endpoint,
        project=settings.norinth_project,
        environment=settings.norinth_environment,
        service="claims-review-assistant",
        capture_content=settings.capture_content,
    )
    norinth.autoinstrument()
    norinth.instrument_fastapi(app, system="claims-review-assistant")


def record_prompt_release(request: Any) -> None:
    norinth.prompt(
        prompt_id=request.prompt_id,
        version=request.version,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        artifact_ref=request.artifact_ref,
        template=request.template,
        status=request.status,
        owner_ref=request.user_id,
        change_notes=request.change_notes,
        metadata={"tenant_id": request.tenant_id, "user_id": request.user_id},
    )


def record_deployment(request: Any, *, deployment_id: str, provider: str, model: str) -> None:
    norinth.deployment(
        deployment_id=deployment_id,
        version=request.version,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        artifact_ref=request.artifact_ref,
        status=request.status,
        provider=provider,
        model=model,
        prompt_version=request.prompt_version,
        deployed_by=request.user_id,
        metadata={
            "tenant_id": request.tenant_id,
            "user_id": request.user_id,
            "deployment_action": "register",
        },
    )


def record_incident(request: Any, *, provider: str, model: str) -> None:
    norinth.incident(
        incident_id=request.incident_id,
        title=request.title,
        severity=request.severity,
        status=request.status,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        description=request.description,
        detected_by=request.user_id,
        impacted_trace_id=request.impacted_trace_id,
        provider=provider,
        model=model,
        metadata={"tenant_id": request.tenant_id, "user_id": request.user_id},
    )

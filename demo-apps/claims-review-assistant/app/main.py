from __future__ import annotations

from dataclasses import dataclass
from os import getenv

from anthropic import Anthropic
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.observability import configure_observability, record_deployment, record_incident, record_prompt_release


@dataclass(frozen=True)
class ClaimsSettings:
    anthropic_api_key: str | None
    anthropic_model: str
    norinth_api_key: str
    norinth_endpoint: str
    norinth_project: str
    norinth_environment: str
    capture_content: bool


class ClaimReviewRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    application_name: str = Field(min_length=1)
    use_case: str = Field(min_length=1)
    model_purpose: str = Field(min_length=1)
    content: str = Field(min_length=1)


class ClaimReviewResponse(BaseModel):
    workflow: str
    application_name: str
    provider: str
    model: str
    review: str
    usage: dict[str, int]


class ClaimsDeploymentRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    application_name: str = Field(default="Claims Review Assistant", min_length=1)
    workflow_name: str = Field(default="claim.review", min_length=1)
    version: str = Field(min_length=1)
    artifact_ref: str = Field(min_length=1)
    status: str = Field(default="pending_review", min_length=1)
    prompt_version: str | None = None


class ClaimsDeploymentResponse(BaseModel):
    deployment_id: str
    application_name: str
    workflow_name: str
    version: str
    status: str
    provider: str
    model: str


class ClaimsPromptReleaseRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    prompt_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    application_name: str = Field(default="Claims Review Assistant", min_length=1)
    workflow_name: str = Field(default="claim.review", min_length=1)
    artifact_ref: str = Field(min_length=1)
    template: str = Field(min_length=1)
    status: str = Field(default="active", min_length=1)
    change_notes: str | None = None


class ClaimsPromptReleaseResponse(BaseModel):
    prompt_id: str
    version: str
    application_name: str
    workflow_name: str
    status: str
    artifact_ref: str


class ClaimsIncidentRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    status: str = Field(default="open", min_length=1)
    application_name: str = Field(min_length=1)
    workflow_name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    impacted_trace_id: str | None = None


class ClaimsIncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    application_name: str
    workflow_name: str


def load_settings() -> ClaimsSettings:
    return ClaimsSettings(
        anthropic_api_key=getenv("ANTHROPIC_API_KEY"),
        anthropic_model=getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
        norinth_api_key=getenv("NORINTH_API_KEY", "dev"),
        norinth_endpoint=getenv("NORINTH_ENDPOINT", "http://localhost:8001"),
        norinth_project=getenv("NORINTH_PROJECT", "norinth-sandbox"),
        norinth_environment=getenv("NORINTH_ENVIRONMENT", "local"),
        capture_content=getenv("NORINTH_CAPTURE_CONTENT", "false").lower() == "true",
    )

settings = load_settings()

app = FastAPI(title="Claims Review Assistant Demo App")
configure_observability(app, settings)
deployment_registry: dict[str, ClaimsDeploymentResponse] = {}


def deployment_id_for(application_name: str, workflow_name: str) -> str:
    return f"{application_name}:{workflow_name}".lower().replace(" ", "-")


@app.get("/health")
def health():
    return {"ok": bool(settings.anthropic_api_key), "service": "claims-review-assistant", "provider": "anthropic", "model": settings.anthropic_model}


@app.post("/prompts/releases", response_model=ClaimsPromptReleaseResponse)
def release_prompt(request: ClaimsPromptReleaseRequest):
    record_prompt_release(request)
    return ClaimsPromptReleaseResponse(
        prompt_id=request.prompt_id,
        version=request.version,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        status=request.status,
        artifact_ref=request.artifact_ref,
    )


@app.post("/deployments/register", response_model=ClaimsDeploymentResponse)
def register_deployment(request: ClaimsDeploymentRequest):
    deployment_id = deployment_id_for(request.application_name, request.workflow_name)
    record_deployment(request, deployment_id=deployment_id, provider="anthropic", model=settings.anthropic_model)
    deployment = ClaimsDeploymentResponse(
        deployment_id=deployment_id,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        version=request.version,
        status=request.status,
        provider="anthropic",
        model=settings.anthropic_model,
    )
    deployment_registry[deployment_id] = deployment
    return deployment


@app.get("/deployments/current", response_model=ClaimsDeploymentResponse)
def current_deployment():
    if not deployment_registry:
        raise HTTPException(status_code=404, detail="No deployment has been registered")
    return next(reversed(deployment_registry.values()))


@app.post("/incidents/report", response_model=ClaimsIncidentResponse)
def report_incident(request: ClaimsIncidentRequest):
    record_incident(request, provider="anthropic", model=settings.anthropic_model)
    return ClaimsIncidentResponse(
        incident_id=request.incident_id,
        title=request.title,
        severity=request.severity,
        status=request.status,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
    )


@app.post("/workflows/claim-review", response_model=ClaimReviewResponse)
def claim_review(request: ClaimReviewRequest):
    if not settings.anthropic_api_key:
        raise HTTPException(status_code=500, detail="Anthropic API key is not configured")
    client = Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=512,
        system=(
            "You are an insurance operations reviewer. Identify missing documentation, decision risks, and evidence "
            "needed before an analyst proceeds. Do not invent facts not present in the content."
        ),
        messages=[{"role": "user", "content": "\n".join([
            f"Application: {request.application_name}",
            f"Use case: {request.use_case}",
            f"Model purpose: {request.model_purpose}",
            f"Content to analyze: {request.content}",
        ])}],
    )
    usage = response.usage
    input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
    output_tokens = getattr(usage, "output_tokens", 0) if usage else 0
    text = "\n".join(
        block.text
        for block in response.content
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    )
    return ClaimReviewResponse(
        workflow="claim.review",
        application_name=request.application_name,
        provider="anthropic",
        model=getattr(response, "model", settings.anthropic_model),
        review=text,
        usage={"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": input_tokens + output_tokens},
    )

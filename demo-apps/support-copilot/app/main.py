from __future__ import annotations

from dataclasses import dataclass
from os import getenv

from fastapi import FastAPI, HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field

from app.observability import configure_observability, record_deployment, record_incident, record_prompt_release


@dataclass(frozen=True)
class SupportSettings:
    openai_api_key: str | None
    openai_model: str
    norinth_api_key: str
    norinth_endpoint: str
    norinth_project: str
    norinth_environment: str
    capture_content: bool


class SupportSummaryRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    application_name: str = Field(min_length=1)
    use_case: str = Field(min_length=1)
    model_purpose: str = Field(min_length=1)
    content: str = Field(min_length=1)


class SupportSummaryResponse(BaseModel):
    workflow: str
    application_name: str
    provider: str
    model: str
    summary: str
    usage: dict[str, int]


class SupportDeploymentRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    application_name: str = Field(default="Support Copilot", min_length=1)
    workflow_name: str = Field(default="support.summary", min_length=1)
    version: str = Field(min_length=1)
    artifact_ref: str = Field(min_length=1)
    status: str = Field(default="pending_review", min_length=1)
    prompt_version: str | None = None


class SupportDeploymentResponse(BaseModel):
    deployment_id: str
    application_name: str
    workflow_name: str
    version: str
    status: str
    provider: str
    model: str


class SupportPromptReleaseRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    prompt_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    application_name: str = Field(default="Support Copilot", min_length=1)
    workflow_name: str = Field(default="support.summary", min_length=1)
    artifact_ref: str = Field(min_length=1)
    template: str = Field(min_length=1)
    status: str = Field(default="active", min_length=1)
    change_notes: str | None = None


class SupportPromptReleaseResponse(BaseModel):
    prompt_id: str
    version: str
    application_name: str
    workflow_name: str
    status: str
    artifact_ref: str


class SupportIncidentRequest(BaseModel):
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


class SupportIncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    application_name: str
    workflow_name: str


def load_settings() -> SupportSettings:
    return SupportSettings(
        openai_api_key=getenv("OPENAI_API_KEY"),
        openai_model=getenv("OPENAI_MODEL", "gpt-4o-mini"),
        norinth_api_key=getenv("NORINTH_API_KEY", "dev"),
        norinth_endpoint=getenv("NORINTH_ENDPOINT", "http://localhost:8001"),
        norinth_project=getenv("NORINTH_PROJECT", "norinth-sandbox"),
        norinth_environment=getenv("NORINTH_ENVIRONMENT", "local"),
        capture_content=getenv("NORINTH_CAPTURE_CONTENT", "false").lower() == "true",
    )

settings = load_settings()

app = FastAPI(title="Support Copilot Demo App")
configure_observability(app, settings)
deployment_registry: dict[str, SupportDeploymentResponse] = {}


def deployment_id_for(application_name: str, workflow_name: str) -> str:
    return f"{application_name}:{workflow_name}".lower().replace(" ", "-")


@app.get("/health")
def health():
    return {"ok": bool(settings.openai_api_key), "service": "support-copilot", "provider": "openai", "model": settings.openai_model}


@app.post("/prompts/releases", response_model=SupportPromptReleaseResponse)
def release_prompt(request: SupportPromptReleaseRequest):
    record_prompt_release(request)
    return SupportPromptReleaseResponse(
        prompt_id=request.prompt_id,
        version=request.version,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        status=request.status,
        artifact_ref=request.artifact_ref,
    )


@app.post("/deployments/register", response_model=SupportDeploymentResponse)
def register_deployment(request: SupportDeploymentRequest):
    deployment_id = deployment_id_for(request.application_name, request.workflow_name)
    record_deployment(request, deployment_id=deployment_id, provider="openai", model=settings.openai_model)
    deployment = SupportDeploymentResponse(
        deployment_id=deployment_id,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        version=request.version,
        status=request.status,
        provider="openai",
        model=settings.openai_model,
    )
    deployment_registry[deployment_id] = deployment
    return deployment


@app.get("/deployments/current", response_model=SupportDeploymentResponse)
def current_deployment():
    if not deployment_registry:
        raise HTTPException(status_code=404, detail="No deployment has been registered")
    return next(reversed(deployment_registry.values()))


@app.post("/incidents/report", response_model=SupportIncidentResponse)
def report_incident(request: SupportIncidentRequest):
    record_incident(request, provider="openai", model=settings.openai_model)
    return SupportIncidentResponse(
        incident_id=request.incident_id,
        title=request.title,
        severity=request.severity,
        status=request.status,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
    )


@app.post("/workflows/support-summary", response_model=SupportSummaryResponse)
def support_summary(request: SupportSummaryRequest):
    if not settings.openai_api_key:
        raise HTTPException(status_code=500, detail="OpenAI API key is not configured")
    client = OpenAI(api_key=settings.openai_api_key)
    response = client.responses.create(
        model=settings.openai_model,
        instructions=(
            "You are a support operations assistant. Summarize the provided support content, identify customer impact, "
            "and list any follow-up actions. Be concise and operational."
        ),
        input="\n".join([
            f"Application: {request.application_name}",
            f"Use case: {request.use_case}",
            f"Model purpose: {request.model_purpose}",
            f"Content to analyze: {request.content}",
        ]),
    )
    usage = response.usage
    return SupportSummaryResponse(
        workflow="support.summary",
        application_name=request.application_name,
        provider="openai",
        model=getattr(response, "model", settings.openai_model),
        summary=response.output_text,
        usage={
            "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
            "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
            "total_tokens": getattr(usage, "total_tokens", 0) if usage else 0,
        },
    )

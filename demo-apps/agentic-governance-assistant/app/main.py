from __future__ import annotations

from dataclasses import dataclass
from os import getenv
from time import perf_counter

from anthropic import Anthropic
from fastapi import FastAPI, HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field

from app.observability import (
    configure_observability,
    record_agent_run,
    record_deployment,
    record_eval_result,
    record_guardrail,
    record_incident,
    record_prompt_release,
    record_retrieval,
    record_tool_call,
)


@dataclass(frozen=True)
class AgenticSettings:
    openai_api_key: str | None
    openai_model: str
    anthropic_api_key: str | None
    anthropic_model: str
    norinth_api_key: str
    norinth_endpoint: str
    norinth_project: str
    norinth_environment: str
    capture_content: bool


@dataclass(frozen=True)
class AIResponse:
    provider: str
    text: str
    model: str
    usage: dict[str, int]


class GovernanceReviewRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    application_name: str = Field(min_length=1)
    use_case: str = Field(min_length=1)
    model_purpose: str = Field(min_length=1)
    content: str = Field(min_length=1)


class ProviderResult(BaseModel):
    provider: str
    model: str
    output: str
    usage: dict[str, int]


class GovernanceReviewResponse(BaseModel):
    workflow: str
    application_name: str
    results: list[ProviderResult]


class AgenticDeploymentRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    application_name: str = Field(default="Agentic Governance Assistant", min_length=1)
    workflow_name: str = Field(default="agentic.governance.review", min_length=1)
    version: str = Field(min_length=1)
    artifact_ref: str = Field(min_length=1)
    status: str = Field(default="pending_review", min_length=1)
    prompt_version: str | None = None


class AgenticDeploymentResponse(BaseModel):
    deployment_id: str
    application_name: str
    workflow_name: str
    version: str
    status: str
    providers: list[str]
    models: list[str]


class AgenticPromptReleaseRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    prompt_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    application_name: str = Field(default="Agentic Governance Assistant", min_length=1)
    workflow_name: str = Field(default="agentic.governance.review", min_length=1)
    artifact_ref: str = Field(min_length=1)
    template: str = Field(min_length=1)
    status: str = Field(default="active", min_length=1)
    change_notes: str | None = None


class AgenticPromptReleaseResponse(BaseModel):
    prompt_id: str
    version: str
    application_name: str
    workflow_name: str
    status: str
    artifact_ref: str


class AgenticIncidentRequest(BaseModel):
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
    provider: str | None = None
    model: str | None = None


class AgenticIncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    status: str
    application_name: str
    workflow_name: str


def load_settings() -> AgenticSettings:
    return AgenticSettings(
        openai_api_key=getenv("OPENAI_API_KEY"),
        openai_model=getenv("OPENAI_MODEL", "gpt-4o-mini"),
        anthropic_api_key=getenv("ANTHROPIC_API_KEY"),
        anthropic_model=getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
        norinth_api_key=getenv("NORINTH_API_KEY", "dev"),
        norinth_endpoint=getenv("NORINTH_ENDPOINT", "http://localhost:8001"),
        norinth_project=getenv("NORINTH_PROJECT", "norinth-sandbox"),
        norinth_environment=getenv("NORINTH_ENVIRONMENT", "local"),
        capture_content=getenv("NORINTH_CAPTURE_CONTENT", "false").lower() == "true",
    )

settings = load_settings()

app = FastAPI(title="Agentic Governance Assistant Demo App")
configure_observability(app, settings)
deployment_registry: dict[str, AgenticDeploymentResponse] = {}


def deployment_id_for(application_name: str, workflow_name: str) -> str:
    return f"{application_name}:{workflow_name}".lower().replace(" ", "-")


@app.get("/health")
def health():
    return {
        "ok": bool(settings.openai_api_key) and bool(settings.anthropic_api_key),
        "service": "agentic-governance-assistant",
        "providers": [
            {"provider": "openai", "configured": bool(settings.openai_api_key), "model": settings.openai_model},
            {"provider": "anthropic", "configured": bool(settings.anthropic_api_key), "model": settings.anthropic_model},
        ],
    }


@app.post("/prompts/releases", response_model=AgenticPromptReleaseResponse)
def release_prompt(request: AgenticPromptReleaseRequest):
    record_prompt_release(request)
    return AgenticPromptReleaseResponse(
        prompt_id=request.prompt_id,
        version=request.version,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        status=request.status,
        artifact_ref=request.artifact_ref,
    )


@app.post("/deployments/register", response_model=AgenticDeploymentResponse)
def register_deployment(request: AgenticDeploymentRequest):
    deployment_id = deployment_id_for(request.application_name, request.workflow_name)
    providers = ["anthropic", "openai"]
    models = [settings.anthropic_model, settings.openai_model]
    record_deployment(request, deployment_id=deployment_id, providers=providers, models=models)
    deployment = AgenticDeploymentResponse(
        deployment_id=deployment_id,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        version=request.version,
        status=request.status,
        providers=providers,
        models=models,
    )
    deployment_registry[deployment_id] = deployment
    return deployment


@app.get("/deployments/current", response_model=AgenticDeploymentResponse)
def current_deployment():
    if not deployment_registry:
        raise HTTPException(status_code=404, detail="No deployment has been registered")
    return next(reversed(deployment_registry.values()))


@app.post("/incidents/report", response_model=AgenticIncidentResponse)
def report_incident(request: AgenticIncidentRequest):
    record_incident(request)
    return AgenticIncidentResponse(
        incident_id=request.incident_id,
        title=request.title,
        severity=request.severity,
        status=request.status,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
    )


@app.post("/workflows/agentic-governance-review", response_model=GovernanceReviewResponse)
def agentic_governance_review(request: GovernanceReviewRequest):
    if not settings.openai_api_key or not settings.anthropic_api_key:
        raise HTTPException(status_code=500, detail="OpenAI and Anthropic API keys are required")

    started = perf_counter()
    prompt = build_workflow_prompt(request)
    retrieval_documents = retrieve_governance_context(request)
    record_retrieval(
        retriever="request-content-retriever",
        query=request.content,
        documents=retrieval_documents,
        duration_ms=(perf_counter() - started) * 1000,
    )

    guardrail_result = evaluate_sensitive_context(request)
    record_guardrail(guardrail_name="sensitive-context-check", result=guardrail_result)

    tool_started = perf_counter()
    risk_profile = build_risk_profile(request, retrieval_documents, guardrail_result)
    record_tool_call(
        tool_name="risk-profile-builder",
        arguments={"content_length": len(request.content), "retrieved_documents": len(retrieval_documents)},
        result=risk_profile,
        duration_ms=(perf_counter() - tool_started) * 1000,
    )

    risk_pass = run_provider_call(
        provider="anthropic",
        instructions=(
            "You are the first step in a multi-provider governance agent. Extract concrete risk signals, "
            "data sensitivity concerns, monitoring requirements, and assumptions from the application content."
        ),
        prompt="\n".join([prompt, "Retrieved governance context:", format_documents(retrieval_documents)]),
    )
    control_pass = run_provider_call(
        provider="openai",
        instructions=(
            "You are the second step in a multi-provider governance agent. Convert the prior risk analysis "
            "into an implementation-ready AI governance monitoring plan with inventory fields, controls, and alerts."
        ),
        prompt="\n".join([prompt, "Risk analysis from prior agent step:", risk_pass.text]),
    )

    eval_score = evaluate_response_completeness(control_pass.text)
    record_eval_result(eval_name="governance-plan-completeness", score=eval_score, threshold=0.6, metadata={"agent_name": "governance-evidence-agent"})
    record_agent_run(
        agent_name="governance-evidence-agent",
        steps=[
            {"name": "retrieve_context", "type": "retrieval", "documents": len(retrieval_documents)},
            {"name": "check_sensitive_context", "type": "guardrail", "decision": guardrail_result["decision"]},
            {"name": "build_risk_profile", "type": "tool", "risk_level": risk_profile["risk_level"]},
            {"name": "analyze_risk", "type": "model_call", "provider": risk_pass.provider, "model": risk_pass.model},
            {"name": "build_controls", "type": "model_call", "provider": control_pass.provider, "model": control_pass.model},
            {"name": "evaluate_plan", "type": "eval", "score": eval_score},
        ],
        outcome="governance review completed",
        duration_ms=(perf_counter() - started) * 1000,
    )
    return GovernanceReviewResponse(
        workflow="agentic.governance.review",
        application_name=request.application_name,
        results=[
            ProviderResult(provider=risk_pass.provider, model=risk_pass.model, output=risk_pass.text, usage=risk_pass.usage),
            ProviderResult(provider=control_pass.provider, model=control_pass.model, output=control_pass.text, usage=control_pass.usage),
        ],
    )


def run_provider_call(*, provider: str, instructions: str, prompt: str) -> AIResponse:
    try:
        if provider == "anthropic":
            return call_anthropic(instructions=instructions, prompt=prompt)
        if provider == "openai":
            return call_openai(instructions=instructions, prompt=prompt)
        raise ValueError(f"Unsupported provider: {provider}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AI provider request failed") from exc


def call_openai(*, instructions: str, prompt: str) -> AIResponse:
    client = OpenAI(api_key=settings.openai_api_key)
    response = client.responses.create(model=settings.openai_model, input=prompt, instructions=instructions)
    usage = response.usage
    return AIResponse(
        provider="openai",
        text=response.output_text,
        model=getattr(response, "model", settings.openai_model),
        usage={
            "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
            "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
            "total_tokens": getattr(usage, "total_tokens", 0) if usage else 0,
        },
    )


def call_anthropic(*, instructions: str, prompt: str) -> AIResponse:
    client = Anthropic(api_key=settings.anthropic_api_key)
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=512,
        system=instructions,
        messages=[{"role": "user", "content": prompt}],
    )
    usage = response.usage
    input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
    output_tokens = getattr(usage, "output_tokens", 0) if usage else 0
    text = "\n".join(
        block.text
        for block in response.content
        if getattr(block, "type", None) == "text" and getattr(block, "text", None)
    )
    return AIResponse(
        provider="anthropic",
        text=text,
        model=getattr(response, "model", settings.anthropic_model),
        usage={"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": input_tokens + output_tokens},
    )


def build_workflow_prompt(request: GovernanceReviewRequest) -> str:
    return "\n".join(
        [
            f"Application: {request.application_name}",
            f"Use case: {request.use_case}",
            f"Model purpose: {request.model_purpose}",
            f"Content to analyze: {request.content}",
        ]
    )


def retrieve_governance_context(request: GovernanceReviewRequest) -> list[dict[str, str | float]]:
    facts = [
        ("application", request.application_name),
        ("use_case", request.use_case),
        ("model_purpose", request.model_purpose),
        ("content", request.content),
    ]
    return [
        {
            "document_id": f"request-{name}",
            "source": "workflow_request",
            "score": 1.0 - (index * 0.1),
            "text": value,
        }
        for index, (name, value) in enumerate(facts)
        if value
    ]


def evaluate_sensitive_context(request: GovernanceReviewRequest) -> dict[str, object]:
    combined = " ".join([request.use_case, request.model_purpose, request.content]).lower()
    rules = {
        "customer_data": ("customer", "account", "support"),
        "insurance_claim": ("claim", "claimant", "police report", "loss statement"),
        "identity_access": ("password", "mfa", "reset"),
    }
    matched_rules = [name for name, terms in rules.items() if any(term in combined for term in terms)]
    score = min(1.0, len(matched_rules) / len(rules))
    decision = "warn" if matched_rules else "allow"
    return {"decision": decision, "score": score, "matched_rules": matched_rules}


def build_risk_profile(
    request: GovernanceReviewRequest,
    documents: list[dict[str, str | float]],
    guardrail_result: dict[str, object],
) -> dict[str, object]:
    matched_rules = guardrail_result.get("matched_rules", [])
    sensitive_signal_count = len(matched_rules) if isinstance(matched_rules, list) else 0
    risk_level = "high" if sensitive_signal_count >= 2 else "medium" if sensitive_signal_count == 1 else "low"
    return {
        "application_name": request.application_name,
        "use_case": request.use_case,
        "risk_level": risk_level,
        "retrieved_documents": len(documents),
        "guardrail_decision": guardrail_result.get("decision"),
        "sensitive_signal_count": sensitive_signal_count,
    }


def format_documents(documents: list[dict[str, str | float]]) -> str:
    return "\n".join(f"- {document['document_id']}: {document['text']}" for document in documents)


def evaluate_response_completeness(response_text: str) -> float:
    required_terms = ("inventory", "control", "monitor", "risk", "alert")
    normalized = response_text.lower()
    matches = sum(1 for term in required_terms if term in normalized)
    return matches / len(required_terms)

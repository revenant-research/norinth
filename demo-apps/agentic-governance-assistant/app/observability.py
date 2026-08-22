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
        service="agentic-governance-assistant",
        capture_content=settings.capture_content,
    )
    norinth.autoinstrument()
    norinth.instrument_fastapi(app, system="agentic-governance-assistant")


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


def record_deployment(request: Any, *, deployment_id: str, providers: list[str], models: list[str]) -> None:
    norinth.deployment(
        deployment_id=deployment_id,
        version=request.version,
        application_name=request.application_name,
        workflow_name=request.workflow_name,
        artifact_ref=request.artifact_ref,
        status=request.status,
        provider="multi-provider",
        model=",".join(models),
        prompt_version=request.prompt_version,
        deployed_by=request.user_id,
        metadata={
            "tenant_id": request.tenant_id,
            "user_id": request.user_id,
            "deployment_action": "register",
            "providers": providers,
            "models": models,
        },
    )


def record_incident(request: Any) -> None:
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
        provider=request.provider,
        model=request.model,
        metadata={"tenant_id": request.tenant_id, "user_id": request.user_id},
    )


def record_retrieval(*, retriever: str, query: Any, documents: list[dict[str, Any]], duration_ms: float) -> None:
    norinth.retrieval(retriever=retriever, query=query, documents=documents, duration_ms=duration_ms)


def record_guardrail(*, guardrail_name: str, result: dict[str, Any]) -> None:
    norinth.guardrail(
        guardrail_name=guardrail_name,
        decision=str(result["decision"]),
        score=float(result["score"]),
        matched_rules=list(result["matched_rules"]),
    )


def record_tool_call(*, tool_name: str, arguments: dict[str, Any], result: dict[str, Any], duration_ms: float) -> None:
    norinth.tool_call(tool_name=tool_name, arguments=arguments, result=result, duration_ms=duration_ms)


def record_eval_result(*, eval_name: str, score: float, threshold: float, metadata: dict[str, Any]) -> None:
    norinth.eval_result(eval_name=eval_name, score=score, threshold=threshold, passed=score >= threshold, metadata=metadata)


def record_agent_run(*, agent_name: str, steps: list[dict[str, Any]], outcome: str, duration_ms: float) -> None:
    norinth.agent_run(agent_name=agent_name, steps=steps, outcome=outcome, duration_ms=duration_ms)

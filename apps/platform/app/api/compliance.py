from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends

from app.dependencies import ActorContext, current_actor, now, scoped_dependency
from app.schemas.events import ScopeFilter
from app.storage.audit import list_audit_logs, record_audit, verify_audit_chain
from app.storage.raw_events import list_events

# The AI-BOM pages through telemetry rather than reading a single fixed window,
# so an inventory larger than one page is not silently dropped (audit finding
# H7). If the safety ceiling is reached, the BOM says so via a property instead
# of quietly under-reporting.
_AIBOM_PAGE = 1000
_AIBOM_MAX_EVENTS = 200_000
# Deterministic namespace so the same portfolio yields a stable serialNumber.
_AIBOM_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def _collect_events(event_type: str, tenant_id, project, environment) -> tuple[list[dict[str, Any]], bool]:
    """Page through all events of a type up to a safety ceiling.

    Returns (events, truncated) so the caller can disclose truncation rather
    than silently capping at a single page.
    """
    collected: list[dict[str, Any]] = []
    offset = 0
    while offset < _AIBOM_MAX_EVENTS:
        page = list_events(
            tenant_id=tenant_id,
            project=project,
            environment=environment,
            event_type=event_type,
            limit=_AIBOM_PAGE,
            offset=offset,
        )
        collected.extend(page)
        if len(page) < _AIBOM_PAGE:
            return collected, False
        offset += _AIBOM_PAGE
    return collected, True

router = APIRouter()


@router.get("/api/compliance/aibom")
def aibom(scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, Any]:
    return generate_aibom(tenant_id=scope.tenant_id, project=scope.project, environment=scope.environment)


@router.get("/api/compliance/framework-coverage")
def framework_coverage(scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, Any]:
    """Per-framework compliance posture rolled up from control assessments."""
    from app.services.governance import build_framework_coverage

    return build_framework_coverage(scope)


@router.get("/api/compliance/audit-packet")
def audit_packet(actor: ActorContext = Depends(current_actor), scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, Any]:
    """Assemble an audit-ready evidence packet for the actor's tenant.

    A single, self-contained export of governance posture that an auditor or a
    certification body (SOC 2, ISO 42001, EU AI Act, healthcare AI assurance programs) can
    review: inventory, framework-mapped control assessments, risk findings,
    governance decisions and exceptions, deployment approvals, incidents,
    material changes, the CycloneDX AI-BOM, and the tamper-evidence status of the
    audit trail. This was named as a missing capability in the audit and is a
    table-stakes feature for the evidence-automation market.
    """
    # Imported here to avoid a circular import at module load
    # (services.governance imports nothing from this module).
    from app.services.governance import (
        build_applications,
        build_change_events,
        build_control_evidence,
        build_decisions,
        build_deployment_gates,
        build_exceptions,
        build_framework_coverage,
        build_incidents,
        build_models,
        build_review_tasks,
        build_risk_register,
        build_summary,
    )
    from app.storage.agents import compute_agent_posture, list_registered_agents, public_posture
    from app.storage.entities import list_providers

    # Exporting evidence is itself an auditable act: record who pulled the
    # packet and for which scope, before assembling it.
    record_audit(
        actor_ref=actor.user_ref,
        action="compliance.audit_packet",
        tenant_id=scope.tenant_id,
        target_type="audit_packet",
        target_id=scope.tenant_id or "platform",
        detail={"project": scope.project, "environment": scope.environment},
    )
    return {
        "packet_version": "2026-01",
        "generated_at": now(),
        "generated_by": actor.user_ref,
        "tenant_id": scope.tenant_id,
        "project": scope.project,
        "environment": scope.environment,
        "posture": build_summary(scope),
        "inventory": {
            "applications": build_applications(scope).get("applications", []),
            "models": build_models(scope).get("models", []),
            "providers": list_providers(
                tenant_id=scope.tenant_id, project=scope.project, environment=scope.environment
            ),
        },
        "framework_coverage": build_framework_coverage(scope).get("framework_coverage", []),
        "control_assessments": build_control_evidence(scope).get("controls", []),
        "risk_findings": build_risk_register(scope).get("risks", []),
        "governance_decisions": build_decisions(scope).get("decisions", []),
        "exceptions": build_exceptions(scope).get("exceptions", []),
        "deployment_gates": build_deployment_gates(scope).get("deployment_gates", []),
        "incidents": build_incidents(scope).get("incidents", []),
        "material_changes": build_change_events(scope).get("changes", []),
        "open_review_tasks": build_review_tasks(scope).get("review_tasks", []),
        "agent_registry": list_registered_agents(scope.tenant_id or ""),
        "agent_posture": public_posture(compute_agent_posture(scope.tenant_id or "")),
        "aibom": generate_aibom(
            tenant_id=scope.tenant_id, project=scope.project, environment=scope.environment
        ),
        "audit_trail": {
            "recent_entries": list_audit_logs(tenant_id=scope.tenant_id, limit=500),
            "integrity": verify_audit_chain(),
        },
    }


def generate_aibom(tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> dict[str, Any]:
    # Fetch events that indicate AI usage, paging through all of them.
    model_calls, t1 = _collect_events("model.call", tenant_id, project, environment)
    retrievals, t2 = _collect_events("retrieval.call", tenant_id, project, environment)
    guardrails, t3 = _collect_events("guardrail.decision", tenant_id, project, environment)
    agent_runs, t4 = _collect_events("agent.run", tenant_id, project, environment)
    truncated = t1 or t2 or t3 or t4

    systems = {}
    providers_in_use = set()
    models_in_use = set()

    for event in model_calls:
        attrs = event.get("attributes", {})
        metadata = attrs.get("metadata", {})
        
        app_name = metadata.get("application_name", "unknown")
        workflow = metadata.get("workflow_name", "unknown")
        provider = attrs.get("provider", "unknown")
        model = attrs.get("model", "unknown")

        providers_in_use.add(provider)
        models_in_use.add(model)

        sys_key = f"{app_name}:{workflow}"
        if sys_key not in systems:
            systems[sys_key] = {
                "application": app_name,
                "workflow": workflow,
                "use_case": metadata.get("use_case", ""),
                "purpose": metadata.get("model_purpose", ""),
                "models": set(),
                "providers": set(),
                "guardrails": set(),
                "retrievers": set(),
                "agents": set()
            }
        
        systems[sys_key]["models"].add(model)
        systems[sys_key]["providers"].add(provider)

    for event in retrievals:
        attrs = event.get("attributes", {})
        metadata = attrs.get("metadata", {})
        app_name = metadata.get("application_name", "unknown")
        workflow = metadata.get("workflow_name", "unknown")
        retriever = attrs.get("retriever", "unknown")
        
        sys_key = f"{app_name}:{workflow}"
        if sys_key in systems:
            systems[sys_key]["retrievers"].add(retriever)

    for event in guardrails:
        attrs = event.get("attributes", {})
        metadata = attrs.get("metadata", {})
        app_name = metadata.get("application_name", "unknown")
        workflow = metadata.get("workflow_name", "unknown")
        guardrail_name = attrs.get("guardrail_name", "unknown")
        
        sys_key = f"{app_name}:{workflow}"
        if sys_key in systems:
            systems[sys_key]["guardrails"].add(guardrail_name)
            
    for event in agent_runs:
        attrs = event.get("attributes", {})
        metadata = attrs.get("metadata", {})
        app_name = metadata.get("application_name", "unknown")
        workflow = metadata.get("workflow_name", "unknown")
        agent_name = attrs.get("agent_name", "unknown")
        
        sys_key = f"{app_name}:{workflow}"
        if sys_key in systems:
            systems[sys_key]["agents"].add(agent_name)

    # Emit a schema-valid CycloneDX 1.6 BOM (audit finding H7). Each AI system is
    # an "application" component; each distinct model is a "machine-learning-
    # model" component with a modelCard; each provider is a "platform" component.
    # Guardrails, retrievers and agents observed for a system are attached to it
    # as namespaced properties, and dependency edges link systems to the models
    # and providers they use, so SBOM tooling accepts and can traverse the BOM.
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []

    def _model_ref(provider: str, model: str) -> str:
        return f"model:{provider}/{model}"

    def _provider_ref(provider: str) -> str:
        return f"provider:{provider}"

    for provider in sorted(providers_in_use):
        components.append({
            "type": "platform",
            "bom-ref": _provider_ref(provider),
            "name": provider,
            "description": "Model provider observed in runtime telemetry",
        })

    seen_models: set[str] = set()
    for data in systems.values():
        for model in data["models"]:
            provider = next(iter(data["providers"]), "unknown")
            ref = _model_ref(provider, model)
            if ref in seen_models:
                continue
            seen_models.add(ref)
            components.append({
                "type": "machine-learning-model",
                "bom-ref": ref,
                "name": model,
                "publisher": provider,
                "modelCard": {
                    "modelParameters": {"task": "text-generation"},
                },
            })

    for sys_key, data in sorted(systems.items()):
        properties = [{"name": "norinth:workflow", "value": data["workflow"]}]
        if data["use_case"]:
            properties.append({"name": "norinth:use_case", "value": data["use_case"]})
        for guardrail in sorted(data["guardrails"]):
            properties.append({"name": "norinth:guardrail", "value": guardrail})
        for retriever in sorted(data["retrievers"]):
            properties.append({"name": "norinth:retriever", "value": retriever})
        for agent in sorted(data["agents"]):
            properties.append({"name": "norinth:agent", "value": agent})
        components.append({
            "type": "application",
            "bom-ref": f"system:{sys_key}",
            "name": data["application"],
            "description": data["purpose"] or data["use_case"] or "AI system observed in runtime telemetry",
            "properties": properties,
        })
        depends_on = sorted({_model_ref(next(iter(data["providers"]), "unknown"), m) for m in data["models"]})
        depends_on += sorted(_provider_ref(p) for p in data["providers"])
        dependencies.append({"ref": f"system:{sys_key}", "dependsOn": depends_on})

    portfolio_ref = "urn:norinth:ai-portfolio"
    metadata: dict[str, Any] = {
        "timestamp": model_calls[0].get("timestamp") if model_calls else now(),
        "component": {
            "type": "application",
            "bom-ref": portfolio_ref,
            "name": "norinth-ai-portfolio",
            "description": "AI Bill of Materials generated from runtime telemetry",
        },
        "tools": {
            "components": [
                {"type": "application", "name": "Norinth", "publisher": "Revenant Research"}
            ]
        },
    }
    if truncated:
        # Never under-report silently: disclose that the ceiling was reached.
        metadata["properties"] = [
            {"name": "norinth:truncated", "value": "true"},
            {"name": "norinth:max_events_scanned", "value": str(_AIBOM_MAX_EVENTS)},
        ]
    dependencies.append({
        "ref": portfolio_ref,
        "dependsOn": [f"system:{sys_key}" for sys_key in sorted(systems)],
    })

    serial = uuid.uuid5(_AIBOM_NAMESPACE, f"{tenant_id}|{project}|{environment}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }

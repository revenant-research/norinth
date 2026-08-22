from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException

from app.schemas.events import ScopeFilter
from app.storage.raw_events import list_events
from app.dependencies import ActorContext, current_actor, scoped_dependency
from app.services.authorization import (
    AuthorizationError,
    ENTERPRISE_SUBSCRIBER,
    GOVERNANCE_ADMIN,
    PERM_NETWORK_READ,
    require_active_actor,
    require_permission,
)
from app.storage.workflow import list_actor_role_assignments

router = APIRouter()


@router.get("/api/compliance/aibom")
def aibom(scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, Any]:
    return generate_aibom(tenant_id=scope.tenant_id, project=scope.project, environment=scope.environment)


def generate_aibom(tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> dict[str, Any]:
    # Fetch events that indicate AI usage
    model_calls = list_events(tenant_id=tenant_id, project=project, environment=environment, event_type="model.call", limit=5000)
    retrievals = list_events(tenant_id=tenant_id, project=project, environment=environment, event_type="retrieval.call", limit=5000)
    guardrails = list_events(tenant_id=tenant_id, project=project, environment=environment, event_type="guardrail.decision", limit=5000)
    agent_runs = list_events(tenant_id=tenant_id, project=project, environment=environment, event_type="agent.run", limit=5000)

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

    # Format output for ISO 42001 and AIBOM standard
    ai_systems_inventory = []
    for sys_key, data in systems.items():
        ai_systems_inventory.append({
            "system_identifier": sys_key,
            "application_name": data["application"],
            "workflow_name": data["workflow"],
            "intended_purpose": data["purpose"],
            "use_case": data["use_case"],
            "components": {
                "models": list(data["models"]),
                "providers": list(data["providers"]),
                "guardrails": list(data["guardrails"]),
                "retrievers": list(data["retrievers"]),
                "agents": list(data["agents"])
            }
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": model_calls[0].get("timestamp") if model_calls else None,
            "component": {
                "type": "application",
                "name": "enterprise-ai-portfolio",
                "description": "Auto-generated AI Bill of Materials from runtime telemetry"
            }
        },
        "providers_in_use": list(providers_in_use),
        "models_in_use": list(models_in_use),
        "ai_systems_inventory": ai_systems_inventory
    }

@router.get("/api/network/vendors")
def list_network_vendors(actor: ActorContext = Depends(current_actor)):
    try:
        require_permission(actor, PERM_NETWORK_READ)
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error))
    assignments = list_actor_role_assignments(actor.user_ref)

    authorized_tenants = [
        a["tenant_id"] for a in assignments
        if a["role"] in {ENTERPRISE_SUBSCRIBER, GOVERNANCE_ADMIN} and a["tenant_id"] is not None
    ]
    
    vendors = []
    for tenant_id in set(authorized_tenants):
        aibom = generate_aibom(tenant_id=tenant_id)
        
        vendors.append({
            "tenant_id": tenant_id,
            "system_count": len(aibom["ai_systems_inventory"]),
            "providers_in_use": aibom["providers_in_use"],
            "models_in_use": aibom["models_in_use"],
            "aibom": aibom
        })
        
    return {"vendors": vendors}

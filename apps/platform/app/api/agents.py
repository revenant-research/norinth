"""Agent registry and agentic-governance posture endpoints (tenant plane)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import ActorContext, current_actor, scoped_dependency
from app.schemas.events import ScopeFilter
from app.services.authorization import (
    PERM_CONFIG_WRITE,
    PERM_LIFECYCLE_MANAGE,
    AuthorizationError,
    require_permission,
)
from app.storage.agents import (
    AUTONOMY_LEVELS,
    compute_agent_posture,
    list_registered_agents,
    load_registered_agent,
    public_posture,
    register_agent,
    retire_agent,
)
from app.storage.audit import record_audit

router = APIRouter()


class AgentRegistrationRequest(BaseModel):
    agent_name: str = Field(min_length=1, max_length=200)
    owner_ref: str = Field(min_length=1)
    autonomy_level: int = Field(ge=0, le=4)
    allowed_tools: list[str] = Field(default_factory=list)
    processes_untrusted_input: bool = False
    accesses_sensitive_data: bool = False
    can_act_externally: bool = False
    human_checkpoint: bool = True
    application_name: str | None = None
    description: str | None = Field(default=None, max_length=2000)


def _tenant(actor: ActorContext, permission: str) -> str:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant user required")
    try:
        require_permission(actor, permission, {"tenant_id": actor.tenant_id})
    except AuthorizationError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return actor.tenant_id


@router.get("/api/agent-registry")
def agent_registry(scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, Any]:
    return {
        "agents": list_registered_agents(scope.tenant_id or ""),
        "autonomy_levels": AUTONOMY_LEVELS,
    }


@router.post("/api/agent-registry")
def register(payload: AgentRegistrationRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _tenant(actor, PERM_CONFIG_WRITE)
    agent = register_agent(
        tenant_id=tenant_id,
        agent_name=payload.agent_name,
        owner_ref=payload.owner_ref,
        autonomy_level=payload.autonomy_level,
        allowed_tools=payload.allowed_tools,
        processes_untrusted_input=payload.processes_untrusted_input,
        accesses_sensitive_data=payload.accesses_sensitive_data,
        can_act_externally=payload.can_act_externally,
        human_checkpoint=payload.human_checkpoint,
        application_name=payload.application_name,
        description=payload.description,
        created_by=actor.user_ref,
    )
    record_audit(
        actor_ref=actor.user_ref,
        action="agent.register",
        tenant_id=tenant_id,
        target_type="agent",
        target_id=agent["agent_id"],
        detail={
            "agent_name": payload.agent_name,
            "autonomy_level": payload.autonomy_level,
            "allowed_tools": sorted(set(payload.allowed_tools)),
        },
    )
    return {"agent": agent}


@router.post("/api/agent-registry/{agent_id}/retire")
def retire(agent_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _tenant(actor, PERM_LIFECYCLE_MANAGE)
    if load_registered_agent(agent_id, tenant_id) is None:
        raise HTTPException(status_code=404, detail="agent not found in this organization")
    agent = retire_agent(agent_id, tenant_id)
    record_audit(actor_ref=actor.user_ref, action="agent.retire", tenant_id=tenant_id, target_type="agent", target_id=agent_id)
    return {"agent": agent}


@router.get("/api/agents/posture")
def agent_posture(scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, Any]:
    """Observed agents reconciled against the registry: shadow agents,
    unauthorized tool use, lethal-trifecta and autonomy-without-oversight."""
    return public_posture(compute_agent_posture(scope.tenant_id or ""))

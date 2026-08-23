from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import ActorContext, current_actor, scoped_dependency
from app.schemas.events import ScopeFilter
from app.services.authorization import (
    PERM_INTAKE_SUBMIT,
    PERM_LIFECYCLE_MANAGE,
    AuthorizationError,
    require_permission,
)
from app.storage.audit import record_audit
from app.storage.intake import (
    AUTONOMY_LEVELS,
    DATA_SENSITIVITY_LEVELS,
    create_intake,
    list_intake,
    load_intake,
    set_intake_status,
)
from app.storage.workflow import refresh_workflow_state

router = APIRouter()


class IntakeRequest(BaseModel):
    application_name: str = Field(min_length=1)
    use_case: str = Field(min_length=1)
    description: str = Field(min_length=1)
    intended_purpose: str = Field(min_length=1)
    data_sensitivity: str = Field(min_length=1)
    autonomy_level: str = Field(min_length=1)
    affects_individuals: bool = False
    project: str = Field(default="default", min_length=1)
    environment: str = Field(default="production", min_length=1)


class LifecycleActionRequest(BaseModel):
    rationale: str = Field(min_length=1)


def _raise_forbidden(error: AuthorizationError) -> None:
    raise HTTPException(status_code=403, detail=str(error))


@router.get("/api/intake")
def intake(scope: ScopeFilter = Depends(scoped_dependency)) -> dict[str, list[dict[str, Any]]]:
    return {"intake": list_intake(**scope.model_dump())}


@router.post("/api/intake")
def submit_intake(payload: IntakeRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    if payload.data_sensitivity not in DATA_SENSITIVITY_LEVELS:
        raise HTTPException(status_code=400, detail=f"data_sensitivity must be one of {DATA_SENSITIVITY_LEVELS}")
    if payload.autonomy_level not in AUTONOMY_LEVELS:
        raise HTTPException(status_code=400, detail=f"autonomy_level must be one of {AUTONOMY_LEVELS}")
    # use case pinned to the submitter's tenant
    tenant_id = actor.tenant_id
    try:
        require_permission(actor, PERM_INTAKE_SUBMIT, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    record = create_intake(
        {
            **payload.model_dump(),
            "tenant_id": tenant_id,
            "submitted_by": actor.user_ref,
        }
    )
    refresh_workflow_state()
    record_audit(
        actor_ref=actor.user_ref,
        action="intake.submit",
        tenant_id=tenant_id,
        target_type="ai_use_case",
        target_id=record["intake_id"],
        detail={"risk_tier": record["risk_tier"], "use_case": record["use_case"]},
    )
    return {"intake": record}


@router.post("/api/intake/{intake_id}/recertify")
def recertify_intake(intake_id: str, payload: LifecycleActionRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    return _lifecycle_transition(intake_id, payload, actor, status="recertified", action="lifecycle.recertify")


@router.post("/api/intake/{intake_id}/retire")
def retire_intake(intake_id: str, payload: LifecycleActionRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    return _lifecycle_transition(intake_id, payload, actor, status="retired", action="lifecycle.retire")


def _lifecycle_transition(
    intake_id: str,
    payload: LifecycleActionRequest,
    actor: ActorContext,
    *,
    status: str,
    action: str,
) -> dict[str, Any]:
    record = load_intake(intake_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Intake record not found")
    try:
        require_permission(actor, PERM_LIFECYCLE_MANAGE, {"tenant_id": record.get("tenant_id")})
    except AuthorizationError as error:
        _raise_forbidden(error)
    updated = set_intake_status(intake_id, status)
    record_audit(
        actor_ref=actor.user_ref,
        action=action,
        tenant_id=record.get("tenant_id"),
        target_type="ai_use_case",
        target_id=intake_id,
        detail={"rationale": payload.rationale, "status": status},
    )
    return {"intake": updated}

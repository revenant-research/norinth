# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""governance policy engine endpoints: policy documents, approval stages, vendors

the policy document is readable by every member of the organization (it
defines their intake form and approval path); writing and activating it
require config.write. stage decisions run through the same guarded decision
path as everything else: permission check, stage-role authority, maker-checker,
and the cross-stage distinct-decider rule, all server-side
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.dependencies import ActorContext, current_actor, scoped_dependency
from app.schemas.events import ScopeFilter
from app.schemas.workflow import substantive_rationale
from app.services.authorization import (
    PERM_CONFIG_WRITE,
    PERM_LIFECYCLE_MANAGE,
    AuthorizationError,
    require_decision,
    require_permission,
    require_stage_role,
)
from app.storage.audit import record_audit
from app.storage.errors import RecordNotFound
from app.storage.intake import RISK_TIERS
from app.storage.policy_engine import (
    MATERIAL_CHANGE_CEILING,
    MAX_INTAKE_FIELDS,
    MAX_STAGES_PER_SUBJECT,
    RECERTIFY_DAYS_FLOOR,
    activate_policy,
    actor_decided_sibling_stage,
    create_policy_draft,
    effective_policy,
    list_decision_roles,
    list_policy_versions,
    list_stages,
    load_policy_version,
    load_stage,
    load_stage_subject,
    load_vendor,
    policy_diff_summary,
    retire_vendor,
    stage_maker,
    stage_subject_undecided,
    stages_for_subject,
    submit_vendor_review,
    upsert_vendor,
    validate_policy_body,
    vendor_coverage,
)
from app.storage.policy_engine import list_vendors as list_vendor_rows
from app.storage.policy_engine import resolve_vendor_policy as resolve_vendor_policy_storage
from app.storage.raw_events import connect
from app.storage.workflow import record_decision, refresh_workflow_state

router = APIRouter()


class PolicyBodyRequest(BaseModel):
    body: dict[str, Any]


class StageDecisionRequest(BaseModel):
    decision: str = Field(min_length=1)
    rationale: str = Field(min_length=1)

    @field_validator("rationale")
    @classmethod
    def _rationale_is_substantive(cls, value: str) -> str:
        return substantive_rationale(value)


class VendorRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    providers: list[str] = Field(min_length=1)
    approved_models: list[str] | None = None
    notes_ref: str | None = Field(default=None, max_length=500)


def _raise_forbidden(error: AuthorizationError) -> None:
    raise HTTPException(status_code=403, detail=str(error))


def _member_tenant(actor: ActorContext) -> str:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant user required")
    return actor.tenant_id


def _config_tenant(actor: ActorContext) -> str:
    tenant_id = _member_tenant(actor)
    try:
        require_permission(actor, PERM_CONFIG_WRITE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    return tenant_id


# --- policy documents -------------------------------------------------------------


@router.get("/api/governance-policy")
def governance_policy(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """the policy in force for the actor's organization, with its provenance"""
    tenant_id = _member_tenant(actor)
    return {
        "policy": effective_policy(tenant_id),
        "decision_roles": list_decision_roles(),
        "risk_tiers": RISK_TIERS,
        "limits": {
            "recertify_days_floor": RECERTIFY_DAYS_FLOOR,
            "max_open_material_changes_ceiling": MATERIAL_CHANGE_CEILING,
            "max_stages": MAX_STAGES_PER_SUBJECT,
            "max_fields": MAX_INTAKE_FIELDS,
        },
    }


@router.get("/api/governance-policy/versions")
def governance_policy_versions(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _config_tenant(actor)
    return {"versions": list_policy_versions(tenant_id)}


@router.post("/api/governance-policy/validate")
def validate_governance_policy(payload: PolicyBodyRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    _config_tenant(actor)
    errors = validate_policy_body(payload.body)
    return {"valid": not errors, "errors": errors}


@router.post("/api/governance-policy/draft")
def draft_governance_policy(payload: PolicyBodyRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _config_tenant(actor)
    try:
        draft = create_policy_draft(tenant_id, payload.body, actor.user_ref)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="policy.draft",
        tenant_id=tenant_id,
        target_type="governance_policy",
        target_id=f"{tenant_id}/v{draft['version']}",
        detail={"version": draft["version"], "body_hash": draft["body_hash"]},
    )
    return {"policy": draft}


@router.post("/api/governance-policy/versions/{version}/activate")
def activate_governance_policy(version: int, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _config_tenant(actor)
    try:
        activated = activate_policy(tenant_id, version, actor.user_ref)
    except RecordNotFound as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"policy": activated}


@router.get("/api/governance-policy/diff")
def governance_policy_diff(
    to_version: int,
    from_version: int | None = None,
    actor: ActorContext = Depends(current_actor),
) -> dict[str, Any]:
    """difference between two versions; with no from_version, against the
    policy currently in force (which may be the platform default)"""
    tenant_id = _config_tenant(actor)
    target = load_policy_version(tenant_id, to_version)
    if target is None:
        raise HTTPException(status_code=404, detail="policy version not found")
    if from_version is None:
        base_body = effective_policy(tenant_id)["body"]
        base_label = "in force"
    else:
        base = load_policy_version(tenant_id, from_version)
        if base is None:
            raise HTTPException(status_code=404, detail="policy version not found")
        base_body = base["body"]
        base_label = f"v{from_version}"
    return {
        "from": base_label,
        "to": f"v{to_version}",
        "diff": policy_diff_summary(base_body, target["body"]),
    }


# --- approval stages --------------------------------------------------------------


@router.get("/api/approval-stages")
def approval_stages(
    subject_type: str | None = None,
    subject_id: str | None = None,
    scope: ScopeFilter = Depends(scoped_dependency),
) -> dict[str, Any]:
    return {
        "approval_stages": list_stages(
            tenant_id=scope.tenant_id, subject_type=subject_type, subject_id=subject_id
        )
    }


@router.post("/api/approval-stages/{stage_id}/decide")
def decide_approval_stage(
    stage_id: str, payload: StageDecisionRequest, actor: ActorContext = Depends(current_actor)
) -> dict[str, Any]:
    """decide one open stage of a governed subject

    server-side rules, in order: the decision must be approve or reject; the
    subject must still be undecided and the stage open (a decided stage is
    terminal); the actor needs the review decision permission in scope, the
    stage's role authority, must not be the subject's maker, and must not have
    decided any other stage of this subject
    """
    if payload.decision not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="stage decisions must be 'approve' or 'reject'")
    try:
        stage = load_stage(stage_id)
    except RecordNotFound as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    with connect() as connection:
        subject = load_stage_subject(connection, stage)
        undecided = stage_subject_undecided(stage, subject)
        maker = stage_maker(connection, stage, subject)
        already_decided_sibling = actor_decided_sibling_stage(connection, stage, actor.user_ref)
    if not undecided:
        raise HTTPException(status_code=409, detail="the subject of this stage has already been decided")
    if stage["status"] in {"approved", "rejected"}:
        raise HTTPException(status_code=409, detail=f"this stage has already been {stage['status']} and is terminal")
    if stage["status"] != "open":
        raise HTTPException(
            status_code=409,
            detail="this stage is not open yet; earlier stages of the sequence must be approved first",
        )
    target = {
        "tenant_id": stage.get("tenant_id"),
        "project": stage.get("project"),
        "environment": stage.get("environment"),
        "application_name": stage.get("application_name"),
        "target_type": "approval_stage",
    }
    try:
        require_decision(actor, target)
        require_stage_role(actor, stage["required_role"], target)
    except AuthorizationError as error:
        _raise_forbidden(error)
    if maker and maker == actor.user_ref:
        raise HTTPException(
            status_code=403,
            detail="Segregation of duties: a user cannot record a decision on work they originated",
        )
    if already_decided_sibling:
        raise HTTPException(
            status_code=403,
            detail="Segregation of duties: each approval stage of a subject must be decided by a different person",
        )
    decision = record_decision("approval_stage", stage_id, payload.decision, payload.rationale, actor.user_ref)
    record_audit(
        actor_ref=actor.user_ref,
        action="stage.decide",
        tenant_id=stage.get("tenant_id"),
        target_type="approval_stage",
        target_id=stage_id,
        detail={
            "decision": payload.decision,
            "subject_type": stage["subject_type"],
            "subject_id": stage["subject_id"],
            "stage_index": stage["stage_index"],
            "required_role": stage["required_role"],
            "policy_tenant": stage["policy_tenant"],
            "policy_version": stage["policy_version"],
        },
    )
    # re-route the queue so an opened next stage reaches its role's assignee
    if stage["subject_type"] == "review_task":
        refresh_workflow_state(
            [
                {
                    "tenant_id": stage.get("tenant_id"),
                    "project": stage.get("project"),
                    "environment": stage.get("environment"),
                    "application_name": stage.get("application_name"),
                }
            ]
        )
    updated_stage = load_stage(stage_id)
    with connect() as connection:
        subject = load_stage_subject(connection, updated_stage)
        stages = stages_for_subject(stage["subject_type"], stage["subject_id"], int(stage["review_round"]))
    return {
        "stage": updated_stage,
        "decision": decision,
        "stages": stages,
        "subject_status": subject.get("status"),
    }


# --- vendor registry --------------------------------------------------------------


def _vendor_with_stages(vendor: dict[str, Any]) -> dict[str, Any]:
    stages = (
        stages_for_subject("vendor_review", vendor["vendor_id"], int(vendor["review_round"]))
        if int(vendor.get("review_round") or 0) > 0
        else []
    )
    return {**vendor, "stages": stages}


@router.get("/api/vendors")
def vendors(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """the vendor registry joined to observed provider telemetry"""
    tenant_id = _member_tenant(actor)
    with connect() as connection:
        vendor_policy = resolve_vendor_policy_storage(connection, tenant_id)
    return {
        "vendors": [_vendor_with_stages(vendor) for vendor in list_vendor_rows(tenant_id)],
        "coverage": vendor_coverage(tenant_id),
        "policy": vendor_policy,
    }


@router.post("/api/vendors")
def create_vendor(payload: VendorRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _config_tenant(actor)
    try:
        vendor = upsert_vendor(
            tenant_id=tenant_id,
            name=payload.name,
            providers=payload.providers,
            approved_models=payload.approved_models,
            notes_ref=payload.notes_ref,
            created_by=actor.user_ref,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="vendor.upsert",
        tenant_id=tenant_id,
        target_type="vendor",
        target_id=vendor["vendor_id"],
        detail={"name": vendor["name"], "providers": vendor["providers"], "status": vendor["status"]},
    )
    return {"vendor": _vendor_with_stages(vendor)}


@router.post("/api/vendors/{vendor_id}/submit-review")
def submit_vendor_for_review(vendor_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _config_tenant(actor)
    try:
        vendor = submit_vendor_review(vendor_id, tenant_id, actor.user_ref)
    except RecordNotFound as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_audit(
        actor_ref=actor.user_ref,
        action="vendor.submit_review",
        tenant_id=tenant_id,
        target_type="vendor",
        target_id=vendor_id,
        detail={"name": vendor["name"], "review_round": vendor["review_round"]},
    )
    return {"vendor": _vendor_with_stages(vendor)}


@router.post("/api/vendors/{vendor_id}/retire")
def retire_vendor_route(vendor_id: str, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    tenant_id = _member_tenant(actor)
    try:
        require_permission(actor, PERM_LIFECYCLE_MANAGE, {"tenant_id": tenant_id})
    except AuthorizationError as error:
        _raise_forbidden(error)
    if load_vendor(vendor_id, tenant_id) is None:
        raise HTTPException(status_code=404, detail="vendor not found in this organization")
    vendor = retire_vendor(vendor_id, tenant_id)
    record_audit(
        actor_ref=actor.user_ref,
        action="vendor.retire",
        tenant_id=tenant_id,
        target_type="vendor",
        target_id=vendor_id,
        detail={"name": vendor["name"]},
    )
    return {"vendor": _vendor_with_stages(vendor)}

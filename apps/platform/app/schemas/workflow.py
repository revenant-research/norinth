from __future__ import annotations

from pydantic import BaseModel, Field


class ControlDefinitionRequest(BaseModel):
    control_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    framework_refs: list[str] = Field(default_factory=list)
    evidence_event_types: list[str] = Field(min_length=1)
    required_fields: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1)


class RiskRuleRequest(BaseModel):
    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    signal: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    framework_refs: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1)


class OwnerPolicyRequest(BaseModel):
    policy_id: str = Field(min_length=1)
    subject_type: str = Field(min_length=1)
    owner_role: str = Field(min_length=1)
    applies_to_status: str | None = None
    source: str = Field(default="configured")


class PlatformUserRequest(BaseModel):
    user_ref: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    status: str = Field(default="active", min_length=1)


class RoleAssignmentRequest(BaseModel):
    user_ref: str = Field(min_length=1)
    role: str = Field(min_length=1)
    status: str = Field(default="active", min_length=1)
    tenant_id: str | None = None
    project: str | None = None
    environment: str | None = None


class ReviewQueuePolicyRequest(BaseModel):
    policy_id: str = Field(min_length=1)
    task_type: str = Field(min_length=1)
    assigned_role: str = Field(min_length=1)
    due_days: int = Field(ge=0)
    escalation_days: int = Field(ge=0)
    source: str = Field(default="configured", min_length=1)


class OwnerAssignmentRequest(BaseModel):
    owner_ref: str = Field(min_length=1)
    actor_ref: str | None = None


class DecisionRequest(BaseModel):
    target_type: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    decision: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    actor_ref: str | None = None


class ExceptionRequest(BaseModel):
    target_type: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    compensating_control: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    actor_ref: str | None = None


class DeploymentGateDecisionRequest(BaseModel):
    rationale: str = Field(min_length=1)


class IngestionKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)

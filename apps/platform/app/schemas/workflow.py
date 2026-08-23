from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

# tokens that carry no reviewer judgement. the dashboard builds a scaffolded
# packet ("Evidence reviewed: no ... Reviewer rationale: not provided"); that
# scaffold alone would pass a min_length=1 guard, so strip it and require
# substantive content before a gate is approved or an incident closed
_RATIONALE_PLACEHOLDERS = {
    "",
    "yes",
    "no",
    "n/a",
    "na",
    "none",
    "tbd",
    "-",
    ".",
    "not provided",
    "not documented",
    "not applicable",
}
_MIN_RATIONALE_CHARS = 12

# fixed labels the dashboard prepends to each packet line; only these are
# stripped before the content check, so a colon in a reviewer's own prose (e.g.
# "evidence bound to sha256:abc") isn't mistaken for a scaffold label
_SCAFFOLD_LABELS = {
    "evidence reviewed",
    "policy basis checked",
    "owner accountability confirmed",
    "reviewer rationale",
    "change impact reviewed",
    "control evidence reviewed",
    "residual risk disposition reviewed",
    "release decision rationale",
    "root cause",
    "impact",
    "remediation completed",
    "recurrence prevention",
}


def substantive_rationale(value: str) -> str:
    """reduce a decision rationale to its reviewer-authored content and require it

    accepts a raw rationale or the dashboard's ``Label: value`` packet. a line
    starting with a known scaffold label is reduced to the text after it, others
    kept whole. placeholders dropped, and the remainder must be at least
    ``_MIN_RATIONALE_CHARS`` chars, so an untouched packet is rejected while prose
    with a colon is not
    """
    substance: list[str] = []
    for line in value.splitlines() or [value]:
        head, sep, tail = line.partition(":")
        candidate = tail.strip() if sep and head.strip().lower() in _SCAFFOLD_LABELS else line.strip()
        if candidate.lower() not in _RATIONALE_PLACEHOLDERS:
            substance.append(candidate)
    joined = " ".join(substance).strip()
    if len(joined) < _MIN_RATIONALE_CHARS:
        raise ValueError(
            "Provide a substantive rationale describing the basis for the decision "
            f"(at least {_MIN_RATIONALE_CHARS} characters of reviewer input)."
        )
    return value.strip()


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

    @field_validator("rationale")
    @classmethod
    def _rationale_is_substantive(cls, value: str) -> str:
        return substantive_rationale(value)


class ExceptionRequest(BaseModel):
    target_type: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    compensating_control: str = Field(min_length=1)
    expires_at: str = Field(min_length=1)
    actor_ref: str | None = None


class DeploymentGateDecisionRequest(BaseModel):
    rationale: str = Field(min_length=1)

    @field_validator("rationale")
    @classmethod
    def _rationale_is_substantive(cls, value: str) -> str:
        return substantive_rationale(value)


class IngestionKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AttestationKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    public_key_pem: str = Field(min_length=40, max_length=4096)

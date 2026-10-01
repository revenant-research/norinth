# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Portable execution-platform contracts. No host-specific identifiers or code."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

CONTRACT_VERSION: Literal["2026-01"] = "2026-01"
Scope = Literal[
    "systems:read", "systems:write", "revisions:write", "observations:write", "authorizations:request", "receipts:write"
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    contract_version: Literal["2026-01"] = CONTRACT_VERSION


class ActionCapability(Contract):
    name: str = Field(min_length=1, max_length=128)
    resource_type: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=128)
    parameter_types: dict[str, Literal["string", "number", "boolean"]] = Field(default_factory=dict, max_length=32)
    reversible: bool = False
    verification_check: str = Field(min_length=1, max_length=128)


class IntegrationCreate(Contract):
    name: str = Field(min_length=1, max_length=128)
    namespace: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")
    project: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=128)
    scopes: list[Scope] = Field(min_length=1, max_length=6)
    capabilities: list[ActionCapability] = Field(default_factory=list, max_length=32)


class SystemInput(Contract):
    external_id: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    resource_type: str = Field(min_length=1, max_length=128)
    purpose: str = Field(default="", max_length=1000)
    legacy_application_name: str | None = Field(default=None, min_length=1, max_length=256)


class RevisionManifest(Contract):
    revision: str = Field(min_length=1, max_length=128)
    artifact_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    models: list[str] = Field(default_factory=list, max_length=64)
    tools: list[str] = Field(default_factory=list, max_length=128)
    resources: list[str] = Field(default_factory=list, max_length=128)
    prompt_refs: list[str] = Field(default_factory=list, max_length=128)
    autonomy_level: int = Field(default=0, ge=0, le=4)
    untrusted_input: bool = False
    sensitive_data: bool = False
    external_action: bool = False
    human_checkpoint: bool = False

    @field_validator("models", "tools", "resources", "prompt_refs")
    @classmethod
    def identifiers(cls, values: list[str]) -> list[str]:
        values = [v.strip() for v in values]
        if any(not v.strip() or len(v) > 256 for v in values) or len(set(values)) != len(values):
            raise ValueError("Identifiers must be nonempty, unique, and at most 256 characters")
        return sorted(values)


class ObservationInput(Contract):
    external_id: str = Field(min_length=1, max_length=256)
    check_id: str = Field(min_length=1, max_length=128)
    result: Literal["passing", "failed", "unknown"]
    observed_at: str = Field(min_length=1, max_length=64)
    revision_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    evidence_ref: str = Field(min_length=1, max_length=512)
    action_digest: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    resource_id: str | None = Field(default=None, min_length=1, max_length=256)


class RuntimePolicy(Contract):
    models: list[str] = Field(default_factory=list, max_length=64)
    tools: list[str] = Field(default_factory=list, max_length=128)
    resources: list[str] = Field(default_factory=list, max_length=128)
    actions: list[str] = Field(default_factory=list, max_length=32)
    remediation_actions: list[str] = Field(default_factory=list, max_length=32)
    action_parameters: dict[str, dict[str, JsonValue]] = Field(default_factory=dict, max_length=32)
    max_autonomy: int = Field(default=0, ge=0, le=4)
    allow_external_action: bool = False
    require_human_checkpoint: bool = True
    allow_routine_releases: bool = False
    required_checks: list[str] = Field(min_length=1, max_length=64)
    trusted_sources: list[str] = Field(min_length=1, max_length=32)
    evidence_max_age_seconds: int = Field(default=86400, ge=60, le=2592000)
    permit_ttl_seconds: int = Field(default=60, ge=1, le=300)

    @field_validator(
        "models", "tools", "resources", "actions", "remediation_actions", "required_checks", "trusted_sources"
    )
    @classmethod
    def identifiers(cls, values: list[str]) -> list[str]:
        return RevisionManifest.identifiers(values)


class ActionInput(Contract):
    capability: str = Field(min_length=1, max_length=128)
    resource_id: str = Field(min_length=1, max_length=256)
    parameters: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)


class AuthorizationInput(Contract):
    revision_id: str = Field(min_length=1, max_length=128)
    purpose: Literal["release", "runtime", "remediation"]
    action: ActionInput | None = None


class ConsumeInput(Contract):
    token: str = Field(min_length=1, max_length=256)
    request: AuthorizationInput


class ReceiptInput(Contract):
    authorization_id: str = Field(min_length=1, max_length=128)
    outcome: Literal["executed", "failed"]
    evidence_ref: str = Field(min_length=1, max_length=512)


class VerificationInput(Contract):
    observation_id: str = Field(min_length=1, max_length=128)


class DecisionInput(Contract):
    rationale: str = Field(min_length=12, max_length=2000)


class ControlDefinition(Contract):
    control_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    resource_types: list[str] = Field(min_length=1, max_length=32)
    check_ids: list[str] = Field(min_length=1, max_length=32)
    framework_refs: list[str] = Field(min_length=1, max_length=64)
    max_age_seconds: int = Field(default=86400, ge=60, le=2592000)

    @field_validator("resource_types", "check_ids", "framework_refs")
    @classmethod
    def identifiers(cls, values: list[str]) -> list[str]:
        return RevisionManifest.identifiers(values)


class ControlPack(Contract):
    pack_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    trusted_sources: list[str] = Field(min_length=1, max_length=32)
    controls: list[ControlDefinition] = Field(min_length=1, max_length=128)

    @field_validator("trusted_sources")
    @classmethod
    def identifiers(cls, values: list[str]) -> list[str]:
        return RevisionManifest.identifiers(values)


class DelegationInput(DecisionInput):
    integration_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    decision: Literal["approve_system", "approve_revision", "activate_policy", "activate_pack", "retire_system"]


class RedeemInput(Contract):
    token: str = Field(min_length=1, max_length=256)


class SubmissionInput(Contract):
    integration_id: str = Field(min_length=1, max_length=128)
    system_id: str = Field(min_length=1, max_length=128)
    manifest: RevisionManifest

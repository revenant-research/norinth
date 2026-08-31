# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""governance policy engine: declarative, versioned policy on the evidence spine

each organization can declare how many approvals a use case needs and which
roles give them, how often things recertify, what evidence a gate demands per
environment, extra intake fields, and how vendors are reviewed. the meaning of
a decision never changes: policy parameterizes the fixed machine, it is not a
workflow designer. see docs/design/governance-policy-engine.md

invariants this module keeps:
* the submitter never decides, and no user decides two stages of one subject
* decisions stay terminal and append-only (they ride record_decision)
* every policy activation is hash-chained in the audit log
* gates only tighten: policy cannot approve without evidence
* roles stay platform-wide; policy references them, never redefines them

the shipped platform default (tenant_id '') encodes today's behavior exactly:
one review stage per tier, no recertification clock, gate attestation driven
by registered attestation keys. an install that never touches policy behaves
as it did before this module existed.

a stage's role requirement is its authority: any role granting at least the
required role's permissions satisfies it. that keeps the seeded single-stage
default (governance_reviewer) open to every role that can decide reviews
today, while a risk_owner stage still refuses a bare reviewer. multiple
people from one role are forced by the distinct-decider rule, not the role
list.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from .entities import decode_json, encode_json, entity_id
from .errors import RecordNotFound
from .intake import RISK_TIERS
from .raw_events import connect
from .workflow import apply_decision_status

POLICY_SCHEMA = "governance-policy/v1"

# validation floors and caps; policy can tighten gates, never relax them
RECERTIFY_DAYS_FLOOR = 30
RECERTIFY_DAYS_CEILING = 3650
MAX_STAGES_PER_SUBJECT = 10
MAX_INTAKE_FIELDS = 20
MAX_FIELD_LENGTH_CAP = 4000
MAX_LABEL_LENGTH = 120
MAX_FIELD_LABEL_LENGTH = 200
# today's gate refuses to approve with any open material change; that floor is
# also the ceiling a policy may declare, so the knob exists in the schema but
# cannot relax the gate below shipped behavior
MATERIAL_CHANGE_CEILING = 0

_FIELD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FIELD_TYPES = {"string", "number", "boolean"}
_STAGE_MODES = {"sequence", "parallel"}

# the decision permission every stage position requires (intake and vendor
# stages are review decisions)
_STAGE_DECISION_PERMISSION = "review.decide"

# the platform default: today's behavior, exactly. one review stage per tier
# decided by any role that can decide reviews, no recertification clock, gate
# attestation left to registered attestation keys, no extra intake fields.
DEFAULT_POLICY_BODY: dict[str, Any] = {
    "schema": POLICY_SCHEMA,
    "intake": {
        "tiers": {
            "limited": {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"},
            "elevated": {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"},
            "high": {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"},
        },
        "fields": [],
    },
    "gates": {
        "environments": {
            "*": {"require_attested_evals": False, "max_open_material_changes": 0},
        }
    },
    "vendors": {"stages": [{"role": "governance_reviewer"}], "recertify_days": 365},
}

# vendor governance detection rule; evaluated by refresh_vendor_posture against
# the registry, not by the generic signal evaluator (like the agent rules)
VENDOR_RISK_RULES = [
    {
        "rule_id": "RISK-VND-001",
        "name": "Unreviewed AI vendor observed in production",
        "signal": "unreviewed_vendor",
        "severity": "High",
        "framework_refs": ["NIST AI RMF GOVERN 6.1", "NIST AI RMF MAP 3.2", "ISO/IEC 42001 A.10.2", "EU AI Act Art 25"],
        "rationale": "Runtime telemetry names every model provider actually in use. A provider with no "
        "approved vendor entry, or a model outside a vendor's approved list, is third-party AI running "
        "without vendor review.",
    },
]

# --- schema -----------------------------------------------------------------------


def ensure_policy_engine_tables(connection) -> None:
    """policy versions, approval stages, vendor registry; idempotent"""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS governance_policies (
            tenant_id TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL,
            status TEXT NOT NULL,
            body TEXT NOT NULL,
            body_hash TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            PRIMARY KEY (tenant_id, version)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_stages (
            stage_id TEXT PRIMARY KEY,
            tenant_id TEXT,
            project TEXT NOT NULL,
            environment TEXT NOT NULL,
            application_name TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            review_round INTEGER NOT NULL DEFAULT 0,
            policy_tenant TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            stage_index INTEGER NOT NULL,
            required_role TEXT NOT NULL,
            label TEXT,
            mode TEXT NOT NULL DEFAULT 'sequence',
            status TEXT NOT NULL,
            decision_id TEXT,
            decided_by TEXT,
            created_at TEXT NOT NULL,
            decided_at TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_registry (
            vendor_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            providers TEXT NOT NULL,
            status TEXT NOT NULL,
            approved_models TEXT,
            notes_ref TEXT,
            review_round INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL,
            submitted_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            reviewed_at TEXT
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_governance_policies_status ON governance_policies(tenant_id, status)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_approval_stages_subject ON approval_stages(subject_type, subject_id, review_round)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_approval_stages_tenant ON approval_stages(tenant_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_vendor_registry_tenant ON vendor_registry(tenant_id, status)")
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_registry_name ON vendor_registry(tenant_id, name)")


def seed_default_policy(connection) -> None:
    """seed governance-policy/v1 version 1 for tenant_id '', active; idempotent"""
    connection.execute(
        """
        INSERT OR IGNORE INTO governance_policies (
            tenant_id, version, status, body, body_hash, created_by, created_at, activated_at
        )
        VALUES ('', 1, 'active', ?, ?, 'system:default', datetime('now'), datetime('now'))
        """,
        (canonical_body(DEFAULT_POLICY_BODY), body_hash(DEFAULT_POLICY_BODY)),
    )


# --- document handling ------------------------------------------------------------


def canonical_body(body: dict[str, Any]) -> str:
    return encode_json(body)


def body_hash(body: dict[str, Any]) -> str:
    return sha256(canonical_body(body).encode("utf-8")).hexdigest()


def _decision_capable_roles(connection) -> dict[str, set[str]]:
    """role -> permission set for every role defined in role_permissions"""
    grants: dict[str, set[str]] = {}
    for row in connection.execute("SELECT role, permission FROM role_permissions").fetchall():
        grants.setdefault(row["role"], set()).add(row["permission"])
    return grants


def list_decision_roles(connection=None) -> list[str]:
    """roles a policy stage may name: platform roles holding review.decide"""
    owned = connection is None
    conn = connect() if owned else connection
    try:
        grants = _decision_capable_roles(conn)
    finally:
        if owned:
            conn.close()
    return sorted(role for role, perms in grants.items() if _STAGE_DECISION_PERMISSION in perms)


def _validate_stages(stages: Any, where: str, grants: dict[str, set[str]], errors: list[str]) -> None:
    if not isinstance(stages, list) or not stages:
        errors.append(f"{where}: stages must be a non-empty list")
        return
    if len(stages) > MAX_STAGES_PER_SUBJECT:
        errors.append(f"{where}: at most {MAX_STAGES_PER_SUBJECT} stages")
        return
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            errors.append(f"{where}: stage {index} must be an object")
            continue
        unknown = set(stage) - {"role", "label"}
        if unknown:
            errors.append(f"{where}: stage {index} has unknown keys: {', '.join(sorted(unknown))}")
        role = stage.get("role")
        if not isinstance(role, str) or not role:
            errors.append(f"{where}: stage {index} must name a role")
        elif role not in grants:
            errors.append(f"{where}: stage {index} references role '{role}', which does not exist")
        elif _STAGE_DECISION_PERMISSION not in grants[role]:
            errors.append(f"{where}: stage {index} role '{role}' does not hold {_STAGE_DECISION_PERMISSION}")
        label = stage.get("label")
        if label is not None and (not isinstance(label, str) or len(label) > MAX_LABEL_LENGTH):
            errors.append(f"{where}: stage {index} label must be a string of at most {MAX_LABEL_LENGTH} characters")


def _validate_recertify_days(value: Any, where: str, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, int) or isinstance(value, bool) or not (RECERTIFY_DAYS_FLOOR <= value <= RECERTIFY_DAYS_CEILING):
        errors.append(f"{where}: recertify_days must be an integer between {RECERTIFY_DAYS_FLOOR} and {RECERTIFY_DAYS_CEILING}")


def _validate_intake(intake: Any, grants: dict[str, set[str]], errors: list[str]) -> None:
    if not isinstance(intake, dict):
        errors.append("intake must be an object")
        return
    unknown = set(intake) - {"tiers", "fields"}
    if unknown:
        errors.append(f"intake has unknown keys: {', '.join(sorted(unknown))}")
    tiers = intake.get("tiers", {})
    if not isinstance(tiers, dict):
        errors.append("intake.tiers must be an object")
        tiers = {}
    for tier, entry in tiers.items():
        where = f"intake.tiers.{tier}"
        if tier not in RISK_TIERS:
            errors.append(f"{where}: unknown risk tier (known tiers: {', '.join(RISK_TIERS)})")
            continue
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue
        unknown = set(entry) - {"stages", "mode", "recertify_days"}
        if unknown:
            errors.append(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
        _validate_stages(entry.get("stages"), where, grants, errors)
        mode = entry.get("mode", "sequence")
        if mode not in _STAGE_MODES:
            errors.append(f"{where}: mode must be one of {sorted(_STAGE_MODES)}")
        _validate_recertify_days(entry.get("recertify_days"), where, errors)
    _validate_fields(intake.get("fields", []), errors)


def _validate_fields(fields: Any, errors: list[str]) -> None:
    if not isinstance(fields, list):
        errors.append("intake.fields must be a list")
        return
    if len(fields) > MAX_INTAKE_FIELDS:
        errors.append(f"intake.fields: at most {MAX_INTAKE_FIELDS} fields")
        return
    seen: set[str] = set()
    for index, field in enumerate(fields):
        where = f"intake.fields[{index}]"
        if not isinstance(field, dict):
            errors.append(f"{where}: must be an object")
            continue
        unknown = set(field) - {"key", "label", "type", "max_length", "required_tiers"}
        if unknown:
            errors.append(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
        key = field.get("key")
        if not isinstance(key, str) or not _FIELD_KEY_RE.match(key):
            errors.append(f"{where}: key must match {_FIELD_KEY_RE.pattern}")
        elif key in seen:
            errors.append(f"{where}: duplicate key '{key}'")
        else:
            seen.add(key)
        label = field.get("label")
        if label is not None and (not isinstance(label, str) or not label or len(label) > MAX_FIELD_LABEL_LENGTH):
            errors.append(f"{where}: label must be a string of at most {MAX_FIELD_LABEL_LENGTH} characters")
        field_type = field.get("type", "string")
        if field_type not in _FIELD_TYPES:
            errors.append(f"{where}: type must be one of {sorted(_FIELD_TYPES)}")
        max_length = field.get("max_length")
        if max_length is not None and (
            not isinstance(max_length, int) or isinstance(max_length, bool) or not (1 <= max_length <= MAX_FIELD_LENGTH_CAP)
        ):
            errors.append(f"{where}: max_length must be an integer between 1 and {MAX_FIELD_LENGTH_CAP}")
        required_tiers = field.get("required_tiers", [])
        if not isinstance(required_tiers, list) or any(tier not in RISK_TIERS for tier in required_tiers):
            errors.append(f"{where}: required_tiers must be a list drawn from {RISK_TIERS}")


def _validate_gates(gates: Any, errors: list[str]) -> None:
    if not isinstance(gates, dict):
        errors.append("gates must be an object")
        return
    unknown = set(gates) - {"environments"}
    if unknown:
        errors.append(f"gates has unknown keys: {', '.join(sorted(unknown))}")
    environments = gates.get("environments", {})
    if not isinstance(environments, dict):
        errors.append("gates.environments must be an object")
        return
    for environment, entry in environments.items():
        where = f"gates.environments.{environment}"
        if not isinstance(environment, str) or not environment or len(environment) > 100:
            errors.append("gates.environments: environment names must be 1-100 characters")
            continue
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue
        unknown = set(entry) - {"require_attested_evals", "max_open_material_changes"}
        if unknown:
            errors.append(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
        attested = entry.get("require_attested_evals", False)
        if not isinstance(attested, bool):
            errors.append(f"{where}: require_attested_evals must be a boolean")
        max_changes = entry.get("max_open_material_changes", 0)
        if not isinstance(max_changes, int) or isinstance(max_changes, bool) or max_changes < 0:
            errors.append(f"{where}: max_open_material_changes must be a non-negative integer")
        elif max_changes > MATERIAL_CHANGE_CEILING:
            # policy may only tighten: the shipped gate refuses to approve with
            # open material changes, and no tenant can configure its way past that
            errors.append(
                f"{where}: max_open_material_changes cannot exceed {MATERIAL_CHANGE_CEILING} (the platform floor)"
            )


def _validate_vendors(vendors: Any, grants: dict[str, set[str]], errors: list[str]) -> None:
    if not isinstance(vendors, dict):
        errors.append("vendors must be an object")
        return
    unknown = set(vendors) - {"stages", "recertify_days"}
    if unknown:
        errors.append(f"vendors has unknown keys: {', '.join(sorted(unknown))}")
    _validate_stages(vendors.get("stages"), "vendors", grants, errors)
    _validate_recertify_days(vendors.get("recertify_days"), "vendors", errors)


def validate_policy_body(body: Any, connection=None) -> list[str]:
    """all validation errors for a policy document; empty means valid

    the body is configuration, not code: no expressions, no templates, and
    unknown structure is rejected outright
    """
    errors: list[str] = []
    if not isinstance(body, dict):
        return ["policy body must be a JSON object"]
    if body.get("schema") != POLICY_SCHEMA:
        errors.append(f"schema must be '{POLICY_SCHEMA}'")
    unknown = set(body) - {"schema", "intake", "gates", "vendors"}
    if unknown:
        errors.append(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    owned = connection is None
    conn = connect() if owned else connection
    try:
        grants = _decision_capable_roles(conn)
    finally:
        if owned:
            conn.close()
    if "intake" in body:
        _validate_intake(body["intake"], grants, errors)
    if "gates" in body:
        _validate_gates(body["gates"], errors)
    if "vendors" in body:
        _validate_vendors(body["vendors"], grants, errors)
    return errors


def _policy_row(row: Any) -> dict[str, Any]:
    record = dict(row)
    record["body"] = decode_json(record["body"], {})
    return record


def active_policy(connection, tenant_id: str | None) -> dict[str, Any]:
    """the tenant's active policy row, or the platform default when none

    always returns a row: the platform default is seeded at migration time
    """
    tid = tenant_id or ""
    if tid:
        row = connection.execute(
            "SELECT * FROM governance_policies WHERE tenant_id = ? AND status = 'active'", (tid,)
        ).fetchone()
        if row is not None:
            return _policy_row(row)
    row = connection.execute(
        "SELECT * FROM governance_policies WHERE tenant_id = '' AND status = 'active'"
    ).fetchone()
    if row is None:
        # unreachable after migration 21; fail safe with the shipped default
        return {"tenant_id": "", "version": 1, "status": "active", "body": DEFAULT_POLICY_BODY, "body_hash": body_hash(DEFAULT_POLICY_BODY)}
    return _policy_row(row)


def _platform_default(connection) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM governance_policies WHERE tenant_id = '' AND status = 'active'"
    ).fetchone()
    if row is None:
        return {"tenant_id": "", "version": 1, "body": DEFAULT_POLICY_BODY, "body_hash": body_hash(DEFAULT_POLICY_BODY)}
    return _policy_row(row)


def resolve_tier_policy(connection, tenant_id: str | None, risk_tier: str) -> dict[str, Any]:
    """stages, mode and recertify_days governing one tier for one tenant

    a tier absent from the tenant document falls back to the platform default's
    entry for that tier, so a tenant can override only what it cares about. the
    returned policy_tenant/policy_version name the row whose entry was used;
    they are what stage rows and packets pin
    """
    policy = active_policy(connection, tenant_id)
    entry = (policy["body"].get("intake", {}).get("tiers", {}) or {}).get(risk_tier)
    if entry is None and policy["tenant_id"] != "":
        policy = _platform_default(connection)
        entry = (policy["body"].get("intake", {}).get("tiers", {}) or {}).get(risk_tier)
    if entry is None:
        entry = {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"}
    return {
        "stages": entry.get("stages") or [{"role": "governance_reviewer"}],
        "mode": entry.get("mode", "sequence"),
        "recertify_days": entry.get("recertify_days"),
        "policy_tenant": policy["tenant_id"],
        "policy_version": policy["version"],
    }


def resolve_gate_policy(connection, tenant_id: str | None, environment: str) -> dict[str, Any]:
    """gate requirements for one environment: tenant env entry, then tenant '*',
    then the platform default's env entry, then its '*'

    require_attested_evals composes with the attestation-keys behavior at the
    caller (policy OR registered keys): policy can add the requirement, never
    remove the keys-based one
    """
    for policy in (active_policy(connection, tenant_id), _platform_default(connection)):
        environments = policy["body"].get("gates", {}).get("environments", {}) or {}
        entry = environments.get(environment)
        if entry is None:
            entry = environments.get("*")
        if entry is not None:
            return {
                "require_attested_evals": bool(entry.get("require_attested_evals", False)),
                "max_open_material_changes": min(int(entry.get("max_open_material_changes", 0)), MATERIAL_CHANGE_CEILING),
                "policy_tenant": policy["tenant_id"],
                "policy_version": policy["version"],
            }
    default = _platform_default(connection)
    return {
        "require_attested_evals": False,
        "max_open_material_changes": 0,
        "policy_tenant": default["tenant_id"],
        "policy_version": default["version"],
    }


def resolve_vendor_policy(connection, tenant_id: str | None) -> dict[str, Any]:
    policy = active_policy(connection, tenant_id)
    entry = policy["body"].get("vendors")
    if entry is None and policy["tenant_id"] != "":
        policy = _platform_default(connection)
        entry = policy["body"].get("vendors")
    if entry is None:
        entry = DEFAULT_POLICY_BODY["vendors"]
    return {
        "stages": entry.get("stages") or [{"role": "governance_reviewer"}],
        "recertify_days": entry.get("recertify_days"),
        "policy_tenant": policy["tenant_id"],
        "policy_version": policy["version"],
    }


def resolve_intake_fields(connection, tenant_id: str | None) -> list[dict[str, Any]]:
    """custom intake fields in force for a tenant; the tenant's list replaces
    the default's when the tenant document declares one"""
    policy = active_policy(connection, tenant_id)
    intake = policy["body"].get("intake", {})
    if "fields" in intake:
        return list(intake.get("fields") or [])
    return list(_platform_default(connection)["body"].get("intake", {}).get("fields") or [])


def effective_policy(tenant_id: str | None) -> dict[str, Any]:
    """the policy governing a tenant right now, with its provenance"""
    with connect() as connection:
        policy = active_policy(connection, tenant_id)
    return {
        "tenant_id": policy["tenant_id"],
        "version": policy["version"],
        "body": policy["body"],
        "body_hash": policy["body_hash"],
        "activated_at": policy.get("activated_at"),
        "source": "tenant" if policy["tenant_id"] else "default",
    }


def list_policy_versions(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM governance_policies WHERE tenant_id = ? ORDER BY version DESC", (tenant_id,)
        ).fetchall()
    return [_policy_row(row) for row in rows]


def load_policy_version(tenant_id: str, version: int) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM governance_policies WHERE tenant_id = ? AND version = ?", (tenant_id, version)
        ).fetchone()
    return None if row is None else _policy_row(row)


def create_policy_draft(tenant_id: str, body: dict[str, Any], actor_ref: str) -> dict[str, Any]:
    """validate and store the next policy version as a draft"""
    if not tenant_id:
        raise ValueError("a tenant_id is required to author a governance policy")
    errors = validate_policy_body(body)
    if errors:
        raise ValueError("invalid policy document: " + "; ".join(errors))
    with connect() as connection:
        row = connection.execute(
            "SELECT COALESCE(MAX(version), 0) AS latest FROM governance_policies WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        version = int(row["latest"]) + 1
        connection.execute(
            """
            INSERT INTO governance_policies (
                tenant_id, version, status, body, body_hash, created_by, created_at, activated_at
            )
            VALUES (?, ?, 'draft', ?, ?, ?, datetime('now'), NULL)
            """,
            (tenant_id, version, canonical_body(body), body_hash(body), actor_ref),
        )
        return _policy_row(
            connection.execute(
                "SELECT * FROM governance_policies WHERE tenant_id = ? AND version = ?", (tenant_id, version)
            ).fetchone()
        )


def activate_policy(tenant_id: str, version: int, actor_ref: str) -> dict[str, Any]:
    """put one version in force; the previous active version is superseded in
    the same transaction. in-flight subjects keep the stages they were
    materialized with, so activation never rewrites open work
    """
    if not tenant_id:
        raise ValueError("a tenant_id is required to activate a governance policy")
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM governance_policies WHERE tenant_id = ? AND version = ?", (tenant_id, version)
        ).fetchone()
        if row is None:
            raise RecordNotFound("policy version not found")
        target = _policy_row(row)
        if target["status"] == "active":
            return target
        if target["status"] == "superseded":
            raise ValueError("a superseded policy version cannot be re-activated; draft a new version")
        # re-validate at activation: role definitions may have changed since drafting
        errors = validate_policy_body(target["body"], connection)
        if errors:
            raise ValueError("policy version is no longer valid: " + "; ".join(errors))
        previous = connection.execute(
            "SELECT * FROM governance_policies WHERE tenant_id = ? AND status = 'active'", (tenant_id,)
        ).fetchone()
        if previous is not None:
            connection.execute(
                "UPDATE governance_policies SET status = 'superseded' WHERE tenant_id = ? AND version = ?",
                (tenant_id, previous["version"]),
            )
        connection.execute(
            "UPDATE governance_policies SET status = 'active', activated_at = datetime('now') WHERE tenant_id = ? AND version = ?",
            (tenant_id, version),
        )
        activated = _policy_row(
            connection.execute(
                "SELECT * FROM governance_policies WHERE tenant_id = ? AND version = ?", (tenant_id, version)
            ).fetchone()
        )
        previous_body = _policy_row(previous)["body"] if previous is not None else _platform_default(connection)["body"]
    from .audit import record_audit

    record_audit(
        actor_ref=actor_ref,
        action="policy.activate",
        tenant_id=tenant_id,
        target_type="governance_policy",
        target_id=f"{tenant_id}/v{version}",
        detail={
            "version": version,
            "body_hash": activated["body_hash"],
            "superseded_version": previous["version"] if previous is not None else None,
            "diff": policy_diff_summary(previous_body, activated["body"]),
        },
    )
    return activated


def _flatten(prefix: str, value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            _flatten(f"{prefix}.{key}" if prefix else str(key), value[key], out)
    else:
        out[prefix] = value


def policy_diff_summary(old_body: dict[str, Any], new_body: dict[str, Any]) -> list[str]:
    """compact, human-readable difference between two policy documents

    shown in the activation dialog and recorded in the policy.activate audit
    detail, so the chain shows what each activation changed
    """
    old_flat: dict[str, Any] = {}
    new_flat: dict[str, Any] = {}
    _flatten("", old_body or {}, old_flat)
    _flatten("", new_body or {}, new_flat)
    changes: list[str] = []
    for key in sorted(set(old_flat) | set(new_flat)):
        if key not in old_flat:
            changes.append(f"added {key} = {encode_json(new_flat[key])}")
        elif key not in new_flat:
            changes.append(f"removed {key} (was {encode_json(old_flat[key])})")
        elif old_flat[key] != new_flat[key]:
            changes.append(f"changed {key}: {encode_json(old_flat[key])} -> {encode_json(new_flat[key])}")
    return changes or ["no changes"]


# --- custom intake fields ---------------------------------------------------------


def validate_custom_field_values(
    fields: list[dict[str, Any]], values: dict[str, Any] | None, risk_tier: str
) -> dict[str, Any]:
    """check submitted custom-field values against the policy's declarations

    unknown keys are rejected (the content boundary: only declared, typed,
    length-capped fields are stored), types are enforced, and a field whose
    required_tiers include the computed tier must be present and non-empty
    """
    values = values or {}
    declared = {field["key"]: field for field in fields}
    unknown = set(values) - set(declared)
    if unknown:
        raise ValueError(f"unknown intake fields: {', '.join(sorted(unknown))} (fields are declared in the governance policy)")
    cleaned: dict[str, Any] = {}
    for key, field in declared.items():
        value = values.get(key)
        required = risk_tier in (field.get("required_tiers") or [])
        if value is None or value == "":
            if required:
                label = field.get("label") or key
                raise ValueError(f"intake field '{label}' is required for risk tier '{risk_tier}'")
            continue
        field_type = field.get("type", "string")
        if field_type == "string":
            if not isinstance(value, str):
                raise ValueError(f"intake field '{key}' must be a string")
            max_length = int(field.get("max_length") or 500)
            if len(value) > max_length:
                raise ValueError(f"intake field '{key}' exceeds its maximum length of {max_length} characters")
            cleaned[key] = value
        elif field_type == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"intake field '{key}' must be a number")
            cleaned[key] = value
        elif field_type == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"intake field '{key}' must be a boolean")
            cleaned[key] = value
    return cleaned


# --- approval stages --------------------------------------------------------------


def _stage_id(subject_type: str, subject_id: str, review_round: int, stage_index: int) -> str:
    return entity_id("approval-stage", subject_type, subject_id, review_round, stage_index)


def materialize_stages(
    connection,
    *,
    subject_type: str,
    subject_id: str,
    review_round: int,
    tenant_id: str | None,
    project: str,
    environment: str,
    application_name: str,
    stages: list[dict[str, Any]],
    mode: str,
    policy_tenant: str,
    policy_version: int,
) -> bool:
    """materialize a subject's stage checklist from the policy in force now

    idempotent per (subject, round): stages already materialized are never
    rewritten, which is what pins in-flight work to the policy version it
    started under. returns True when stages were created
    """
    existing = connection.execute(
        "SELECT 1 FROM approval_stages WHERE subject_type = ? AND subject_id = ? AND review_round = ? LIMIT 1",
        (subject_type, subject_id, review_round),
    ).fetchone()
    if existing is not None:
        return False
    for index, stage in enumerate(stages):
        status = "open" if (mode == "parallel" or index == 0) else "pending"
        connection.execute(
            """
            INSERT OR IGNORE INTO approval_stages (
                stage_id, tenant_id, project, environment, application_name, subject_type, subject_id,
                review_round, policy_tenant, policy_version, stage_index, required_role, label, mode,
                status, decision_id, decided_by, created_at, decided_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, datetime('now'), NULL)
            """,
            (
                _stage_id(subject_type, subject_id, review_round, index),
                tenant_id,
                project,
                environment,
                application_name,
                subject_type,
                subject_id,
                review_round,
                policy_tenant,
                policy_version,
                index,
                stage["role"],
                stage.get("label"),
                mode,
                status,
            ),
        )
    return True


def materialize_intake_stages(connection, task_id: str, record: dict[str, Any], risk_tier: str) -> None:
    """stage checklist for an intake review, from the active policy at submission"""
    tier_policy = resolve_tier_policy(connection, record.get("tenant_id"), risk_tier)
    materialize_stages(
        connection,
        subject_type="review_task",
        subject_id=task_id,
        review_round=0,
        tenant_id=record.get("tenant_id"),
        project=record["project"],
        environment=record["environment"],
        application_name=record["application_name"],
        stages=tier_policy["stages"],
        mode=tier_policy["mode"],
        policy_tenant=tier_policy["policy_tenant"],
        policy_version=tier_policy["policy_version"],
    )


def _stage_row(row: Any) -> dict[str, Any]:
    return dict(row)


def load_stage(stage_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT * FROM approval_stages WHERE stage_id = ?", (stage_id,)).fetchone()
    if row is None:
        raise RecordNotFound("approval stage not found")
    return _stage_row(row)


def list_subject_stages(
    connection, subject_type: str, subject_id: str, review_round: int | None = None
) -> list[dict[str, Any]]:
    if review_round is None:
        rows = connection.execute(
            "SELECT * FROM approval_stages WHERE subject_type = ? AND subject_id = ? ORDER BY review_round, stage_index",
            (subject_type, subject_id),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT * FROM approval_stages WHERE subject_type = ? AND subject_id = ? AND review_round = ? ORDER BY stage_index",
            (subject_type, subject_id, review_round),
        ).fetchall()
    return [_stage_row(row) for row in rows]


def stages_for_subject(subject_type: str, subject_id: str, review_round: int | None = None) -> list[dict[str, Any]]:
    with connect() as connection:
        return list_subject_stages(connection, subject_type, subject_id, review_round)


def list_stages(
    *, tenant_id: str | None = None, subject_type: str | None = None, subject_id: str | None = None
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if tenant_id:
        clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if subject_type:
        clauses.append("subject_type = :subject_type")
        params["subject_type"] = subject_type
    if subject_id:
        clauses.append("subject_id = :subject_id")
        params["subject_id"] = subject_id
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM approval_stages {where} ORDER BY created_at DESC, subject_id, review_round, stage_index",
            params,
        ).fetchall()
    return [_stage_row(row) for row in rows]


def load_stage_subject(connection, stage: dict[str, Any]) -> dict[str, Any]:
    """the work item a stage belongs to, with its current status"""
    if stage["subject_type"] == "review_task":
        row = connection.execute("SELECT * FROM review_tasks WHERE task_id = ?", (stage["subject_id"],)).fetchone()
        if row is None:
            raise RecordNotFound("review task for this stage no longer exists")
        return dict(row)
    if stage["subject_type"] == "vendor_review":
        row = connection.execute("SELECT * FROM vendor_registry WHERE vendor_id = ?", (stage["subject_id"],)).fetchone()
        if row is None:
            raise RecordNotFound("vendor for this stage no longer exists")
        return dict(row)
    raise ValueError(f"unsupported stage subject type: {stage['subject_type']}")


def stage_subject_undecided(stage: dict[str, Any], subject: dict[str, Any]) -> bool:
    """whether the stage's subject is still open to stage decisions"""
    if stage["subject_type"] == "review_task":
        return subject.get("status") == "open"
    if stage["subject_type"] == "vendor_review":
        return subject.get("status") == "under_review" and int(subject.get("review_round") or 0) == int(stage["review_round"])
    return False


def stage_maker(connection, stage: dict[str, Any], subject: dict[str, Any]) -> str | None:
    """who originated the stage's subject; that person never decides it"""
    if stage["subject_type"] == "review_task":
        if subject.get("task_type") in {"intake_review", "recertification_review"}:
            row = connection.execute(
                "SELECT submitted_by FROM ai_use_cases WHERE intake_id = ?", (subject.get("change_id"),)
            ).fetchone()
            return None if row is None else row["submitted_by"]
        return subject.get("submitted_by") or subject.get("created_by")
    if stage["subject_type"] == "vendor_review":
        return subject.get("submitted_by") or subject.get("created_by")
    return None


def actor_decided_sibling_stage(connection, stage: dict[str, Any], actor_ref: str) -> bool:
    """cross-stage segregation of duties: one person, one stage per subject"""
    row = connection.execute(
        """
        SELECT 1 FROM approval_stages
        WHERE subject_type = ? AND subject_id = ? AND review_round = ?
          AND stage_id != ? AND decided_by = ?
        LIMIT 1
        """,
        (stage["subject_type"], stage["subject_id"], stage["review_round"], stage["stage_id"], actor_ref),
    ).fetchone()
    return row is not None


def _notify_stage_opened(connection, stage: dict[str, Any]) -> None:
    from app.services.notifications import emit, public_base_url

    if stage["subject_type"] == "review_task":
        link = f"{public_base_url()}/#review/{stage['subject_id']}"
        subject_label = stage.get("application_name") or stage["subject_id"]
    else:
        link = f"{public_base_url()}/#vendors"
        subject_label = stage.get("application_name") or "vendor"
    emit(
        connection,
        tenant_id=stage.get("tenant_id"),
        event_type="review.stage_opened",
        subject=f"Approval stage open: {stage.get('label') or stage['required_role']} for {subject_label}",
        text=(
            f"Stage {int(stage['stage_index']) + 1} ({stage.get('label') or stage['required_role']}) is now open for "
            f"{subject_label}. It requires a decision by a holder of the {stage['required_role']} role."
        ),
        data={
            "stage_id": stage["stage_id"],
            "subject_type": stage["subject_type"],
            "subject_id": stage["subject_id"],
            "required_role": stage["required_role"],
        },
        to_roles=[stage["required_role"]],
        link=link,
    )


def _roll_up_subject(connection, stage: dict[str, Any], decision: str) -> None:
    """the subject approves only when every stage approved; any rejection
    rejects it. review tasks reuse apply_decision_status so the use-case
    lifecycle moves exactly as a direct task decision moves it"""
    if stage["subject_type"] == "review_task":
        apply_decision_status(connection, "review_task", stage["subject_id"], decision)
    elif stage["subject_type"] == "vendor_review":
        status = "approved" if decision == "approve" else "rejected"
        connection.execute(
            """
            UPDATE vendor_registry
            SET status = ?, reviewed_at = datetime('now'), updated_at = datetime('now')
            WHERE vendor_id = ? AND review_round = ? AND status = 'under_review'
            """,
            (status, stage["subject_id"], stage["review_round"]),
        )


def apply_stage_decision(connection, stage: dict[str, Any], decision: str, decision_id: str, actor_ref: str) -> None:
    """transition one open stage and roll the subject up

    called from record_decision's stage hook inside the decision transaction.
    a stage, once decided, never changes: the update is guarded on the open
    status, and a replayed decision finds nothing open to move
    """
    status = "approved" if decision == "approve" else "rejected"
    moved = connection.execute(
        """
        UPDATE approval_stages
        SET status = ?, decision_id = ?, decided_by = ?, decided_at = datetime('now')
        WHERE stage_id = ? AND status = 'open'
        """,
        (status, decision_id, actor_ref, stage["stage_id"]),
    )
    if getattr(moved, "rowcount", 1) == 0:
        return
    if status == "rejected":
        _roll_up_subject(connection, stage, "reject")
        return
    siblings = list_subject_stages(connection, stage["subject_type"], stage["subject_id"], int(stage["review_round"]))
    if all(sibling["status"] == "approved" for sibling in siblings):
        _roll_up_subject(connection, stage, "approve")
        return
    if stage.get("mode") == "sequence":
        next_pending = next((sibling for sibling in siblings if sibling["status"] == "pending"), None)
        if next_pending is not None:
            connection.execute(
                "UPDATE approval_stages SET status = 'open' WHERE stage_id = ? AND status = 'pending'",
                (next_pending["stage_id"],),
            )
            next_pending = dict(next_pending, status="open")
            _notify_stage_opened(connection, next_pending)


def sync_decision_to_stages(
    connection, target_type: str, target_id: str, decision: str, actor_ref: str, decision_id: str
) -> None:
    """keep stage rows consistent with a recorded decision

    called by record_decision inside its transaction. an approval_stage
    decision drives the stage transition and roll-up. a direct review_task
    decision (the pre-policy wire surface) stamps the task's single stage so
    the packet still shows who decided which stage under which policy; the
    API refuses that path when a multi-stage policy governs the task
    """
    if decision not in {"approve", "reject"}:
        return
    if target_type == "approval_stage":
        row = connection.execute("SELECT * FROM approval_stages WHERE stage_id = ?", (target_id,)).fetchone()
        if row is not None:
            apply_stage_decision(connection, dict(row), decision, decision_id, actor_ref)
        return
    if target_type == "review_task":
        stages = list_subject_stages(connection, "review_task", target_id, 0)
        if len(stages) == 1 and stages[0]["status"] == "open":
            status = "approved" if decision == "approve" else "rejected"
            connection.execute(
                """
                UPDATE approval_stages
                SET status = ?, decision_id = ?, decided_by = ?, decided_at = datetime('now')
                WHERE stage_id = ? AND status = 'open'
                """,
                (status, decision_id, actor_ref, stages[0]["stage_id"]),
            )


# --- recertification --------------------------------------------------------------


def _parse_db_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def age_recertifications() -> int:
    """open a recertification review for approved systems past their tier's clock

    run by the maintenance worker: recertification turns on the calendar, not
    on telemetry. one task per (use case, certification timestamp), so a due
    system is asked once per certification, not once per pass. returns how
    many tasks were opened
    """
    opened = 0
    now = datetime.now(UTC)
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM ai_use_cases WHERE status IN ('approved', 'recertified')"
        ).fetchall()
        for row in rows:
            record = dict(row)
            tier_policy = resolve_tier_policy(connection, record.get("tenant_id"), record.get("risk_tier") or "limited")
            days = tier_policy.get("recertify_days")
            if not days:
                continue
            anchor = _parse_db_ts(record.get("updated_at"))
            if anchor is None or now <= anchor + timedelta(days=int(days)):
                continue
            task_id = entity_id("review-task", "recertification", record["intake_id"], record["updated_at"])
            title = f"Recertification due: {record['application_name']} / {record['use_case']}"
            rationale = (
                f"Risk tier '{record['risk_tier']}' requires recertification every {days} days under governance "
                f"policy {tier_policy['policy_tenant'] or 'default'}/v{tier_policy['policy_version']}. "
                f"Last certified {record['updated_at']}."
            )
            result = connection.execute(
                """
                INSERT OR IGNORE INTO review_tasks (
                    task_id, change_id, tenant_id, project, environment, application_name, task_type,
                    status, priority, title, rationale, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'recertification_review', 'open', 'medium', ?, ?, datetime('now'), datetime('now'))
                """,
                (
                    task_id,
                    record["intake_id"],
                    record.get("tenant_id"),
                    record["project"],
                    record["environment"],
                    record["application_name"],
                    title,
                    rationale,
                ),
            )
            if getattr(result, "rowcount", 0) > 0:
                opened += 1
    return opened


def close_recertification_tasks(connection, intake_id: str) -> None:
    """close open recertification tasks when the use case is recertified or retired"""
    connection.execute(
        """
        UPDATE review_tasks SET status = 'closed', updated_at = datetime('now')
        WHERE task_type = 'recertification_review' AND change_id = ? AND status = 'open'
        """,
        (intake_id,),
    )


# --- vendor registry --------------------------------------------------------------


def _vendor_row(row: Any) -> dict[str, Any]:
    record = dict(row)
    record["providers"] = decode_json(record.get("providers"), [])
    record["approved_models"] = decode_json(record.get("approved_models"), None)
    return record


def upsert_vendor(
    *,
    tenant_id: str,
    name: str,
    providers: list[str],
    approved_models: list[str] | None,
    notes_ref: str | None,
    created_by: str,
) -> dict[str, Any]:
    """create or update a vendor entry; edits keep the review state untouched
    except that editing an approved vendor's provider or model surface sends it
    back to draft (its review no longer covers what it declares)"""
    if not tenant_id:
        raise ValueError("a tenant_id is required to register a vendor")
    if not providers:
        raise ValueError("a vendor must name at least one provider")
    vendor_id = entity_id("vendor", tenant_id, name)
    normalized = sorted({provider.strip().lower() for provider in providers if provider.strip()})
    models = sorted({model.strip() for model in approved_models if model.strip()}) if approved_models else None
    with connect() as connection:
        existing = connection.execute("SELECT * FROM vendor_registry WHERE vendor_id = ?", (vendor_id,)).fetchone()
        if existing is None:
            connection.execute(
                """
                INSERT INTO vendor_registry (
                    vendor_id, tenant_id, name, providers, status, approved_models, notes_ref,
                    review_round, created_by, created_at, updated_at, reviewed_at
                )
                VALUES (?, ?, ?, ?, 'draft', ?, ?, 0, ?, datetime('now'), datetime('now'), NULL)
                """,
                (vendor_id, tenant_id, name, encode_json(normalized), encode_json(models) if models is not None else None, notes_ref, created_by),
            )
        else:
            current = _vendor_row(existing)
            surface_changed = current["providers"] != normalized or current["approved_models"] != models
            status = current["status"]
            if surface_changed and status in {"approved", "recertify_due"}:
                status = "draft"
            connection.execute(
                """
                UPDATE vendor_registry
                SET providers = ?, approved_models = ?, notes_ref = ?, status = ?, updated_at = datetime('now')
                WHERE vendor_id = ?
                """,
                (encode_json(normalized), encode_json(models) if models is not None else None, notes_ref, status, vendor_id),
            )
        return _vendor_row(connection.execute("SELECT * FROM vendor_registry WHERE vendor_id = ?", (vendor_id,)).fetchone())


def list_vendors(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM vendor_registry WHERE tenant_id = ? ORDER BY name", (tenant_id,)
        ).fetchall()
    return [_vendor_row(row) for row in rows]


def load_vendor(vendor_id: str, tenant_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM vendor_registry WHERE vendor_id = ? AND tenant_id = ?", (vendor_id, tenant_id)
        ).fetchone()
    return None if row is None else _vendor_row(row)


def submit_vendor_review(vendor_id: str, tenant_id: str, actor_ref: str) -> dict[str, Any]:
    """start a review round: materialize stages from the vendor policy in force

    each round gets its own stage rows; earlier rounds' stages are evidence and
    are never rewritten. the submitter is the maker for segregation of duties
    """
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM vendor_registry WHERE vendor_id = ? AND tenant_id = ?", (vendor_id, tenant_id)
        ).fetchone()
        if row is None:
            raise RecordNotFound("vendor not found in this organization")
        vendor = _vendor_row(row)
        if vendor["status"] == "under_review":
            return vendor
        if vendor["status"] == "retired":
            raise ValueError("a retired vendor cannot be submitted for review")
        vendor_policy = resolve_vendor_policy(connection, tenant_id)
        review_round = int(vendor["review_round"]) + 1
        connection.execute(
            """
            UPDATE vendor_registry
            SET status = 'under_review', review_round = ?, submitted_by = ?, updated_at = datetime('now')
            WHERE vendor_id = ?
            """,
            (review_round, actor_ref, vendor_id),
        )
        materialize_stages(
            connection,
            subject_type="vendor_review",
            subject_id=vendor_id,
            review_round=review_round,
            tenant_id=tenant_id,
            project="vendor-registry",
            environment="global",
            application_name=vendor["name"],
            stages=vendor_policy["stages"],
            mode="sequence",
            policy_tenant=vendor_policy["policy_tenant"],
            policy_version=vendor_policy["policy_version"],
        )
        first = connection.execute(
            "SELECT * FROM approval_stages WHERE subject_type = 'vendor_review' AND subject_id = ? AND review_round = ? AND status = 'open' ORDER BY stage_index LIMIT 1",
            (vendor_id, review_round),
        ).fetchone()
        if first is not None:
            _notify_stage_opened(connection, dict(first))
        return _vendor_row(connection.execute("SELECT * FROM vendor_registry WHERE vendor_id = ?", (vendor_id,)).fetchone())


def retire_vendor(vendor_id: str, tenant_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM vendor_registry WHERE vendor_id = ? AND tenant_id = ?", (vendor_id, tenant_id)
        ).fetchone()
        if row is None:
            raise RecordNotFound("vendor not found in this organization")
        connection.execute(
            "UPDATE vendor_registry SET status = 'retired', updated_at = datetime('now') WHERE vendor_id = ?",
            (vendor_id,),
        )
        return _vendor_row(connection.execute("SELECT * FROM vendor_registry WHERE vendor_id = ?", (vendor_id,)).fetchone())


def age_vendor_recertifications() -> int:
    """flip approved vendors past the policy's recertification window to
    recertify_due; run by the maintenance worker. returns how many flipped"""
    flipped = 0
    due: list[dict[str, Any]] = []
    now = datetime.now(UTC)
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM vendor_registry WHERE status = 'approved' AND reviewed_at IS NOT NULL"
        ).fetchall()
        for row in rows:
            vendor = _vendor_row(row)
            vendor_policy = resolve_vendor_policy(connection, vendor["tenant_id"])
            days = vendor_policy.get("recertify_days")
            if not days:
                continue
            reviewed = _parse_db_ts(vendor["reviewed_at"])
            if reviewed is None or now <= reviewed + timedelta(days=int(days)):
                continue
            moved = connection.execute(
                "UPDATE vendor_registry SET status = 'recertify_due', updated_at = datetime('now') WHERE vendor_id = ? AND status = 'approved'",
                (vendor["vendor_id"],),
            )
            if getattr(moved, "rowcount", 0) > 0:
                flipped += 1
                due.append(vendor)
                from app.services.notifications import emit, public_base_url

                emit(
                    connection,
                    tenant_id=vendor["tenant_id"],
                    event_type="vendor.recertify_due",
                    subject=f"Vendor recertification due: {vendor['name']}",
                    text=(
                        f"The approval of vendor '{vendor['name']}' is older than the {days}-day recertification "
                        "window the governance policy requires. Until it is re-reviewed, its providers count as "
                        "unreviewed in the risk register."
                    ),
                    data={"vendor_id": vendor["vendor_id"], "recertify_days": days},
                    to_roles=["org_admin", "governance_reviewer"],
                    link=f"{public_base_url()}/#vendors",
                )
    from .audit import record_audit

    for vendor in due:
        record_audit(
            actor_ref="system:policy",
            action="vendor.recertify_due",
            tenant_id=vendor["tenant_id"],
            target_type="vendor",
            target_id=vendor["vendor_id"],
            detail={"name": vendor["name"]},
        )
    return flipped


# --- vendor posture: the registry joined to telemetry -----------------------------


def _observed_provider_usage(connection, tenant_id: str) -> list[dict[str, Any]]:
    """distinct (scope, provider, model) pairs observed in model.call telemetry"""
    rows = connection.execute(
        """
        SELECT DISTINCT project, environment, application_name, provider, model
        FROM sdk_events
        WHERE tenant_id = ? AND event_type = 'model.call'
          AND provider IS NOT NULL AND provider != ''
          AND application_name IS NOT NULL AND application_name != ''
        """,
        (tenant_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _provider_trace_ids(connection, tenant_id: str, scope: dict[str, Any], provider: str, cap: int = 50) -> list[str]:
    rows = connection.execute(
        f"""
        SELECT DISTINCT trace_id FROM sdk_events
        WHERE tenant_id = :tenant_id AND event_type = 'model.call' AND provider = :provider
          AND project = :project AND environment = :environment AND application_name = :application_name
        ORDER BY trace_id LIMIT {int(cap)}
        """,
        {"tenant_id": tenant_id, "provider": provider, **scope},
    ).fetchall()
    return [row["trace_id"] for row in rows if row["trace_id"]]


def vendor_coverage(tenant_id: str) -> dict[str, Any]:
    """observed provider usage reconciled against the registry, read-only

    the same claim the agent registry makes for agents: vendor posture proven
    by production telemetry, not a spreadsheet
    """
    with connect() as connection:
        usage = _observed_provider_usage(connection, tenant_id)
    vendors = list_vendors(tenant_id)
    by_provider: dict[str, dict[str, Any]] = {}
    for vendor in vendors:
        for provider in vendor["providers"]:
            by_provider[provider] = vendor
    providers: dict[str, dict[str, Any]] = {}
    for row in usage:
        provider = str(row["provider"]).strip().lower()
        entry = providers.setdefault(
            provider,
            {"provider": provider, "models": set(), "applications": set(), "vendor": None, "vendor_status": None, "covered": False, "disallowed_models": set()},
        )
        if row.get("model"):
            entry["models"].add(row["model"])
        entry["applications"].add(row["application_name"])
        registered = by_provider.get(provider)
        if registered is not None:
            entry["vendor"] = registered["name"]
            entry["vendor_status"] = registered["status"]
            entry["covered"] = registered["status"] == "approved"
            if registered["status"] == "approved" and registered["approved_models"] is not None and row.get("model"):
                if row["model"] not in registered["approved_models"]:
                    entry["disallowed_models"].add(row["model"])
    return {
        "tenant_id": tenant_id,
        "providers": [
            {
                **entry,
                "models": sorted(entry["models"]),
                "applications": sorted(entry["applications"]),
                "disallowed_models": sorted(entry["disallowed_models"]),
            }
            for entry in sorted(providers.values(), key=lambda item: item["provider"])
        ],
        "summary": {
            "observed_providers": len(providers),
            "covered": sum(1 for entry in providers.values() if entry["covered"]),
            "uncovered": sum(1 for entry in providers.values() if not entry["covered"]),
            "registered_vendors": len(vendors),
        },
    }


def refresh_vendor_posture(tenant_ids: list[str] | None = None) -> None:
    """derive unreviewed-vendor findings from observed provider usage

    a provider seen in model.call telemetry with no approved vendor entry, or
    a model outside an approved vendor's allow-list, raises RISK-VND-001 for
    each application using it. findings resolve through human decisions like
    every other rule; reviewer decisions survive recompute
    """
    from .governance_policy import write_rule_finding

    rule = VENDOR_RISK_RULES[0]
    with connect() as connection:
        tenants = [
            row["tenant_id"]
            for row in connection.execute(
                "SELECT DISTINCT tenant_id FROM sdk_events WHERE event_type = 'model.call' AND tenant_id IS NOT NULL AND tenant_id != ''"
            ).fetchall()
        ]
        if tenant_ids is not None:
            wanted = set(tenant_ids)
            tenants = [tenant for tenant in tenants if tenant in wanted]
        for tenant_id in tenants:
            vendor_by_provider: dict[str, dict[str, Any]] = {}
            for row in connection.execute(
                "SELECT * FROM vendor_registry WHERE tenant_id = ?", (tenant_id,)
            ).fetchall():
                vendor = _vendor_row(row)
                for provider in vendor["providers"]:
                    vendor_by_provider[provider] = vendor
            for usage in _observed_provider_usage(connection, tenant_id):
                provider = str(usage["provider"]).strip().lower()
                scope = {
                    "project": usage["project"],
                    "environment": usage["environment"],
                    "application_name": usage["application_name"],
                }
                app_context = {"tenant_id": tenant_id, **scope}
                registered = vendor_by_provider.get(provider)
                if registered is None or registered["status"] != "approved":
                    detail = (
                        f"Provider '{provider}' observed in production with no approved vendor entry"
                        if registered is None
                        else f"Provider '{provider}' observed in production; vendor '{registered['name']}' is {registered['status']}, not approved"
                    )
                    scoped_rule = dict(rule, rule_id=f"{rule['rule_id']}:{provider}")
                    write_rule_finding(
                        connection,
                        app_context,
                        scoped_rule,
                        _provider_trace_ids(connection, tenant_id, scope, usage["provider"]),
                        detail,
                    )
                elif registered["approved_models"] is not None and usage.get("model") and usage["model"] not in registered["approved_models"]:
                    scoped_rule = dict(rule, rule_id=f"{rule['rule_id']}:{provider}:{usage['model']}")
                    write_rule_finding(
                        connection,
                        app_context,
                        scoped_rule,
                        _provider_trace_ids(connection, tenant_id, scope, usage["provider"]),
                        f"Model '{usage['model']}' from provider '{provider}' is outside vendor '{registered['name']}'s approved model list",
                    )


# --- packet evidence --------------------------------------------------------------


def build_policy_evidence(tenant_id: str | None) -> dict[str, Any]:
    """the governance_policy section of the audit packet: the active document,
    its hash, and the version history whose activations are hash-chained in
    the audit log via policy.activate entries"""
    active = effective_policy(tenant_id)
    history = [
        {
            "version": row["version"],
            "status": row["status"],
            "body_hash": row["body_hash"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "activated_at": row.get("activated_at"),
        }
        for row in (list_policy_versions(tenant_id) if tenant_id else [])
    ]
    return {"active": active, "history": history}

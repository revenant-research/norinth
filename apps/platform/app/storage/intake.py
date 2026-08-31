# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from typing import Any

from .entities import decode_json, encode_json, entity_id
from .errors import DomainError
from .raw_events import connect

# inputs to the risk tier; order matters, higher index is higher risk
DATA_SENSITIVITY_LEVELS = ["public", "internal", "confidential", "restricted"]
AUTONOMY_LEVELS = ["assistive", "supervised", "autonomous"]
RISK_TIERS = ["limited", "elevated", "high"]


def init_intake() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_use_cases (
                intake_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                use_case TEXT NOT NULL,
                description TEXT NOT NULL,
                intended_purpose TEXT NOT NULL,
                data_sensitivity TEXT NOT NULL,
                autonomy_level TEXT NOT NULL,
                affects_individuals INTEGER NOT NULL DEFAULT 0,
                risk_tier TEXT NOT NULL,
                status TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ai_use_cases_scope ON ai_use_cases(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_ai_use_cases_status ON ai_use_cases(status)")


def compute_risk_tier(data_sensitivity: str, autonomy_level: str, affects_individuals: bool) -> str:
    """risk tier from intake attributes: data sensitivity and autonomy drive it,
    escalated when the system affects decisions about individuals"""
    sensitivity_score = _level_index(DATA_SENSITIVITY_LEVELS, data_sensitivity)
    autonomy_score = _level_index(AUTONOMY_LEVELS, autonomy_level)
    score = sensitivity_score + autonomy_score + (1 if affects_individuals else 0)
    if data_sensitivity == "restricted" or score >= 4:
        return "high"
    if score >= 2:
        return "elevated"
    return "limited"


def _level_index(levels: list[str], value: str) -> int:
    try:
        return levels.index(value)
    except ValueError:
        return 0


def create_intake(record: dict[str, Any]) -> dict[str, Any]:
    risk_tier = compute_risk_tier(
        record["data_sensitivity"],
        record["autonomy_level"],
        bool(record.get("affects_individuals")),
    )
    intake_id = entity_id(
        "ai-use-case",
        record.get("tenant_id"),
        record["project"],
        record["environment"],
        record["application_name"],
        record["use_case"],
    )
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO ai_use_cases (
                intake_id, tenant_id, project, environment, application_name, use_case,
                description, intended_purpose, data_sensitivity, autonomy_level,
                affects_individuals, risk_tier, status, submitted_by, custom_fields, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted', ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(intake_id) DO UPDATE SET
                description=excluded.description,
                intended_purpose=excluded.intended_purpose,
                data_sensitivity=excluded.data_sensitivity,
                autonomy_level=excluded.autonomy_level,
                affects_individuals=excluded.affects_individuals,
                risk_tier=excluded.risk_tier,
                custom_fields=excluded.custom_fields,
                updated_at=datetime('now')
            """,
            (
                intake_id,
                record.get("tenant_id"),
                record["project"],
                record["environment"],
                record["application_name"],
                record["use_case"],
                record["description"],
                record["intended_purpose"],
                record["data_sensitivity"],
                record["autonomy_level"],
                1 if record.get("affects_individuals") else 0,
                risk_tier,
                record["submitted_by"],
                encode_json(record["custom_fields"]) if record.get("custom_fields") else None,
            ),
        )
        _seed_intake_review_task(connection, intake_id, record, risk_tier)
        return _decode_intake(connection.execute("SELECT * FROM ai_use_cases WHERE intake_id = ?", (intake_id,)).fetchone())


def _decode_intake(row: Any) -> dict[str, Any]:
    record = dict(row)
    record["custom_fields"] = decode_json(record.get("custom_fields"), {})
    return record


def _seed_intake_review_task(connection, intake_id: str, record: dict[str, Any], risk_tier: str) -> None:
    """route an intake_review task; refresh_workflow_state assigns role and
    owner from policy, like material-change reviews"""
    task_id = entity_id("review-task", "intake", intake_id)
    priority = "high" if risk_tier == "high" else "medium"
    title = f"Intake review: {record['application_name']} / {record['use_case']}"
    rationale = (
        f"AI use case submitted with risk tier '{risk_tier}'. "
        f"Purpose: {record['intended_purpose']}. Data sensitivity: {record['data_sensitivity']}. "
        f"Autonomy: {record['autonomy_level']}."
    )
    connection.execute(
        """
        INSERT INTO review_tasks (
            task_id, change_id, tenant_id, project, environment, application_name, task_type,
            status, priority, title, rationale, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'intake_review', 'open', ?, ?, ?, datetime('now'), datetime('now'))
        ON CONFLICT(task_id) DO UPDATE SET
            priority=excluded.priority,
            title=excluded.title,
            rationale=excluded.rationale,
            updated_at=datetime('now')
        """,
        (
            task_id,
            intake_id,
            record.get("tenant_id"),
            record["project"],
            record["environment"],
            record["application_name"],
            priority,
            title,
            rationale,
        ),
    )
    # materialize the approval-stage checklist from the policy active right
    # now; a resubmission of the same use case keeps its existing stages, so
    # in-flight work stays pinned to the policy it started under (imported
    # lazily: policy_engine imports RISK_TIERS from this module)
    from .policy_engine import materialize_intake_stages

    materialize_intake_stages(connection, task_id, record, risk_tier)


def list_intake(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if tenant_id:
        clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if project:
        clauses.append("project = :project")
        params["project"] = project
    if environment:
        clauses.append("environment = :environment")
        params["environment"] = environment
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as connection:
        rows = connection.execute(f"SELECT * FROM ai_use_cases {where} ORDER BY updated_at DESC", params).fetchall()
    return [_decode_intake(row) for row in rows]


def load_intake(intake_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM ai_use_cases WHERE intake_id = ?", (intake_id,)).fetchone()
    return None if row is None else _decode_intake(row)


def intake_submitter(intake_id: str) -> str | None:
    """submitter of a use case, for maker-checker on intake review tasks"""
    with connect() as connection:
        row = connection.execute("SELECT submitted_by FROM ai_use_cases WHERE intake_id = ?", (intake_id,)).fetchone()
    return None if row is None else row["submitted_by"]


def set_intake_status(intake_id: str, status: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute("SELECT 1 FROM ai_use_cases WHERE intake_id = ?", (intake_id,)).fetchone()
        if row is None:
            raise DomainError("intake record not found")
        connection.execute(
            "UPDATE ai_use_cases SET status = ?, updated_at = datetime('now') WHERE intake_id = ?",
            (status, intake_id),
        )
        if status in {"recertified", "retired"}:
            # the recertification clock restarts (or stops); an open reminder
            # task for the old certification is done
            from .policy_engine import close_recertification_tasks

            close_recertification_tasks(connection, intake_id)
        return _decode_intake(connection.execute("SELECT * FROM ai_use_cases WHERE intake_id = ?", (intake_id,)).fetchone())

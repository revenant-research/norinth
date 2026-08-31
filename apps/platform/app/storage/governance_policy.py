# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import re
from typing import Any

from . import db
from .entities import as_object, decode_json, encode_json, entity_id
from .raw_events import connect, deserialize_raw_event

# whole-word agentic terms; substring matching false-positives (e.g
# "stool-sample-tracker" matching "tool"), and this is secondary to real
# tool.call telemetry
_AGENTIC_TERMS = re.compile(r"\b(agent|agents|agentic|tool|tools|orchestrat\w+)\b")

SUPPORTED_RISK_SIGNALS = {
    "provider_dependency",
    "missing_guardrail",
    "missing_eval",
    "missing_agent_run",
    "operational_errors",
    "retired_system_telemetry",
    # agentic signals, evaluated by storage/agents.py against the registry, not
    # by the generic event evaluator
    "unregistered_agent",
    "unauthorized_tool",
    "agent_trifecta",
    "autonomy_without_oversight",
    # vendor signal, evaluated by storage/policy_engine.py against the vendor registry
    "unreviewed_vendor",
}

DEFAULT_CONTROLS = [
    {
        "control_id": "AI-INV-001",
        "name": "AI system inventory is maintained from runtime usage",
        "framework_refs": ["NIST AI RMF MAP 1.1", "ISO/IEC 42001 A.5.2"],
        "evidence_event_types": ["model.call"],
        "required_fields": ["application_name", "provider", "model", "workflow_name"],
        "rationale": "An AI inventory must be grounded in observed application, model, provider, and workflow usage.",
    },
    {
        "control_id": "AI-LOG-001",
        "name": "AI requests are traceable to workflow and actor context",
        "framework_refs": ["NIST AI RMF GOVERN 1.6", "EU AI Act Art 26", "SOC 2 CC7.2"],
        "evidence_event_types": ["trace.completed"],
        "required_fields": ["trace_id", "workflow_name", "user_id"],
        "rationale": "Governance review requires traceable request context, actor metadata, and workflow linkage.",
    },
    {
        "control_id": "AI-DATA-001",
        "name": "Prompt and response content is summarized or hashed by default",
        "framework_refs": ["NIST AI RMF MEASURE 2.6", "SOC 2 CC6.1"],
        "evidence_event_types": ["model.call"],
        "required_fields": ["prompt.hash", "response.hash"],
        "rationale": "Runtime evidence should support auditability while limiting raw content capture by default.",
    },
    {
        "control_id": "AI-RAG-001",
        "name": "Retrieval context is linked to AI workflow traces",
        "framework_refs": ["NIST AI RMF MAP 2.3", "NIST AI RMF MEASURE 2.7"],
        "evidence_event_types": ["retrieval.call"],
        "required_fields": ["retriever", "document_count", "trace_id"],
        "rationale": "RAG systems require evidence of retrieved sources and trace linkage.",
    },
    {
        "control_id": "AI-TOOL-001",
        "name": "Tool execution is recorded for agentic workflows",
        "framework_refs": ["NIST AI RMF GOVERN 6.1", "NIST AI RMF MANAGE 2.3"],
        "evidence_event_types": ["tool.call"],
        "required_fields": ["tool_name", "trace_id", "status"],
        "rationale": "Agentic systems require auditable tool-use evidence.",
    },
    {
        "control_id": "AI-GRD-001",
        "name": "Guardrail decisions are captured for monitored AI workflows",
        "framework_refs": ["NIST AI RMF MANAGE 1.3", "ISO/IEC 42001 A.8.2"],
        "evidence_event_types": ["guardrail.decision"],
        "required_fields": ["guardrail_name", "decision", "matched_rules"],
        "rationale": "Policy, safety, and privacy controls require recorded guardrail decisions and matched rules.",
    },
    {
        "control_id": "AI-EVAL-001",
        "name": "Evaluation results are captured for AI workflow quality evidence",
        "framework_refs": ["NIST AI RMF MEASURE 2.1", "NIST AI RMF MEASURE 2.5"],
        "evidence_event_types": ["eval.result"],
        "required_fields": ["eval_name", "score", "threshold", "passed"],
        "rationale": "AI quality and safety claims require measurable eval results and thresholds.",
    },
    {
        "control_id": "AI-AGT-001",
        "name": "Agent runs are summarized with ordered steps and outcomes",
        "framework_refs": ["NIST AI RMF MAP 5.1", "NIST AI RMF MANAGE 2.4"],
        "evidence_event_types": ["agent.run"],
        "required_fields": ["agent_name", "step_count", "outcome"],
        "rationale": "Agent governance requires run-level evidence, ordered steps, and outcomes.",
    },
    {
        "control_id": "AI-OPS-001",
        "name": "SDK telemetry health and fail-open operation are visible",
        "framework_refs": ["SOC 2 CC7.2", "NIST AI RMF GOVERN 1.5"],
        "evidence_event_types": ["sdk.health"],
        "required_fields": ["mode", "fail_open", "failed_sends"],
        "rationale": "Governance telemetry must itself be observable, including delivery failures and fail-open behavior.",
    },
]

DEFAULT_RISK_RULES = [
    {
        "rule_id": "RISK-TPD-001",
        "name": "Third-party AI dependency",
        "signal": "provider_dependency",
        "severity": "Medium",
        "framework_refs": ["NIST AI RMF MAP 3.2", "NIST AI RMF GOVERN 6.1"],
        "rationale": "Observed external model provider usage creates vendor and third-party AI dependency risk.",
    },
    {
        "rule_id": "RISK-CTL-001",
        "name": "Missing guardrail evidence",
        "signal": "missing_guardrail",
        "severity": "High",
        "framework_refs": ["NIST AI RMF MANAGE 1.3"],
        "rationale": "Applications with model usage but no guardrail evidence lack runtime safety-control support.",
    },
    {
        "rule_id": "RISK-EVL-001",
        "name": "Missing evaluation evidence",
        "signal": "missing_eval",
        "severity": "High",
        "framework_refs": ["NIST AI RMF MEASURE 2.1"],
        "rationale": "Applications with model usage but no eval results lack measurable quality evidence.",
    },
    {
        "rule_id": "RISK-AGT-001",
        "name": "Agentic workflow without agent run evidence",
        "signal": "missing_agent_run",
        "severity": "High",
        "framework_refs": ["NIST AI RMF MAP 5.1", "NIST AI RMF MANAGE 2.4"],
        "rationale": "Agentic use cases require agent run evidence and step traceability.",
    },
    {
        "rule_id": "RISK-OPS-001",
        "name": "Operational reliability failures",
        "signal": "operational_errors",
        "severity": "High",
        "framework_refs": ["NIST AI RMF MANAGE 4.1", "SOC 2 CC7.2"],
        "rationale": "Failed model or workflow events are operational reliability evidence.",
    },
    {
        "rule_id": "RISK-LCY-001",
        "name": "Telemetry observed from a retired system",
        "signal": "retired_system_telemetry",
        "severity": "High",
        "framework_refs": ["NIST AI RMF GOVERN 1.7"],
        "rationale": "A system recorded as retired is still emitting production telemetry: either the "
        "retirement record is wrong or the system was never actually shut down. Decommissioning must be "
        "verifiable.",
    },
]



def _preserve_decided_status(
    connection,
    table: str,
    id_column: str,
    row_id: str,
    computed_status: str,
    computed_statuses: set[str],
) -> str:
    """status to write, preserving a human decision

    if the existing status is not one of the recomputed values it was set by a
    reviewer (accepted, waived, ...) and is kept; otherwise use the computed one
    """
    existing = connection.execute(
        f"SELECT status FROM {table} WHERE {id_column} = ?", (row_id,)
    ).fetchone()
    if existing and existing["status"] and existing["status"] not in computed_statuses:
        return existing["status"]
    return computed_status


def init_governance_policy() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS control_library (
                tenant_id TEXT NOT NULL DEFAULT '',
                control_id TEXT NOT NULL,
                name TEXT NOT NULL,
                framework_refs TEXT NOT NULL,
                evidence_event_types TEXT NOT NULL,
                required_fields TEXT NOT NULL,
                rationale TEXT NOT NULL,
                PRIMARY KEY (tenant_id, control_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_rules (
                tenant_id TEXT NOT NULL DEFAULT '',
                rule_id TEXT NOT NULL,
                name TEXT NOT NULL,
                signal TEXT NOT NULL,
                severity TEXT NOT NULL,
                framework_refs TEXT NOT NULL,
                rationale TEXT NOT NULL,
                PRIMARY KEY (tenant_id, rule_id)
            )
            """
        )
        try:
            connection.execute("ALTER TABLE risk_rules ADD COLUMN signal TEXT NOT NULL DEFAULT 'provider_dependency'")
        except db.OperationalError:
            pass
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS control_assessments (
                assessment_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                control_id TEXT NOT NULL,
                control_name TEXT NOT NULL,
                status TEXT NOT NULL,
                framework_refs TEXT NOT NULL,
                evidence_event_types TEXT NOT NULL,
                required_fields TEXT NOT NULL,
                evidence_trace_ids TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                rationale TEXT NOT NULL,
                evaluated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_findings (
                finding_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                risk TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                rationale TEXT NOT NULL,
                framework_refs TEXT NOT NULL,
                evidence_trace_ids TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                evaluated_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_control_assessments_scope ON control_assessments(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_risk_findings_scope ON risk_findings(tenant_id, project, environment)")

        # seed default controls
        for ctrl in DEFAULT_CONTROLS:
            connection.execute(
                """
                INSERT OR IGNORE INTO control_library (
                    tenant_id, control_id, name, framework_refs, evidence_event_types, required_fields, rationale
                ) VALUES ('', ?, ?, ?, ?, ?, ?)
                """,
                (
                    ctrl["control_id"],
                    ctrl["name"],
                    encode_json(ctrl["framework_refs"]),
                    encode_json(ctrl["evidence_event_types"]),
                    encode_json(ctrl["required_fields"]),
                    ctrl["rationale"]
                )
            )

        # seed default risk rules, including the agentic and vendor ones
        from .agents import AGENT_RISK_RULES
        from .policy_engine import VENDOR_RISK_RULES

        for rule in [*DEFAULT_RISK_RULES, *AGENT_RISK_RULES, *VENDOR_RISK_RULES]:
            connection.execute(
                """
                INSERT OR IGNORE INTO risk_rules (
                    rule_id, name, signal, severity, framework_refs, rationale
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    rule["rule_id"],
                    rule["name"],
                    rule["signal"],
                    rule["severity"],
                    encode_json(rule["framework_refs"]),
                    rule["rationale"]
                )
            )

def refresh_governance_assessments(scopes: list[dict[str, Any]] | None = None) -> None:
    from .lifecycle import _applications_in_scope

    with connect() as connection:
        applications = _applications_in_scope(connection, scopes)
        controls_by_tenant: dict[str, list[dict[str, Any]]] = {}
        rules_by_tenant: dict[str, list[dict[str, Any]]] = {}
        for application in applications:
            app_context = dict(application)
            tid = app_context.get("tenant_id") or ""
            if tid not in controls_by_tenant:
                controls_by_tenant[tid] = list_control_library(connection, tid)
                rules_by_tenant[tid] = list_risk_rules(connection, tid)
            events = list_application_events(connection, app_context)
            assess_controls(connection, app_context, controls_by_tenant[tid], events)
            assess_risk_rules(connection, app_context, rules_by_tenant[tid], events)


def list_control_library(connection, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """platform default controls (tenant_id '') overlaid with this tenant's
    overrides; a tenant never sees another tenant's"""
    tid = tenant_id or ""
    rows = connection.execute(
        "SELECT * FROM control_library WHERE tenant_id IN ('', ?) ORDER BY control_id", (tid,)
    ).fetchall()
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        record = dict(row)
        if record["control_id"] not in merged or record["tenant_id"] != "":
            merged[record["control_id"]] = record
    return [
        {
            **record,
            "framework_refs": decode_json(record["framework_refs"], []),
            "evidence_event_types": decode_json(record["evidence_event_types"], []),
            "required_fields": decode_json(record["required_fields"], []),
        }
        for record in merged.values()
    ]


def list_risk_rules(connection, tenant_id: str | None = None) -> list[dict[str, Any]]:
    tid = tenant_id or ""
    rows = connection.execute(
        "SELECT * FROM risk_rules WHERE tenant_id IN ('', ?) ORDER BY rule_id", (tid,)
    ).fetchall()
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        record = dict(row)
        if record["rule_id"] not in merged or record["tenant_id"] != "":
            merged[record["rule_id"]] = record
    return [
        {
            **record,
            "framework_refs": decode_json(record["framework_refs"], []),
        }
        for record in merged.values()
    ]


def list_application_events(connection, app_context: dict[str, Any]) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT raw_event FROM sdk_events
        WHERE project = :project
          AND environment = :environment
          AND (
            application_name = :application_name
            OR event_type = 'sdk.health'
          )
          AND (
            (:tenant_id IS NULL AND tenant_id IS NULL)
            OR tenant_id = :tenant_id
          )
        ORDER BY id
        """,
        app_context,
    ).fetchall()
    return [dict_event(row["raw_event"]) for row in rows]


def dict_event(raw_event: str) -> dict[str, Any]:
    # decrypt transparently when raw-event encryption is on; {} for anything
    # unparseable
    try:
        return deserialize_raw_event(raw_event)
    except Exception:
        return decode_json(raw_event, {})


# evidence lists on assessments and findings are bounded: they are samples
# that let a reviewer pull the underlying traces, not a replica of history
_EVIDENCE_TRACE_CAP = 200


def _assessment_id(app_context: dict[str, Any], control: dict[str, Any]) -> str:
    return entity_id(
        "control-assessment",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        control["control_id"],
    )


def assess_controls(connection, app_context: dict[str, Any], controls: list[dict[str, Any]], events: list[dict[str, Any]]) -> None:
    for control in controls:
        evidence = [
            event
            for event in events
            if event.get("type") in control["evidence_event_types"]
            and event_satisfies_required_fields(event, control["required_fields"])
        ]
        trace_ids = sorted({event["trace_id"] for event in evidence if event.get("trace_id")})
        _write_assessment(
            connection,
            app_context,
            control,
            "passing" if evidence else "missing",
            trace_ids,
            len(evidence),
        )


def _write_assessment(
    connection,
    app_context: dict[str, Any],
    control: dict[str, Any],
    computed_status: str,
    trace_ids: list[str],
    evidence_count: int,
) -> None:
    assessment_id = _assessment_id(app_context, control)
    # keep a human decision (e.g. "waived") across recompute; only the
    # passing/missing statuses are recomputed, a reviewer's decision sticks
    # until a human changes it
    status = _preserve_decided_status(
        connection, "control_assessments", "assessment_id", assessment_id, computed_status, {"passing", "missing"}
    )
    connection.execute(
            """
            INSERT OR REPLACE INTO control_assessments (
                assessment_id, tenant_id, project, environment, application_name, control_id, control_name,
                status, framework_refs, evidence_event_types, required_fields, evidence_trace_ids,
                evidence_count, rationale, evaluated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                assessment_id,
                app_context.get("tenant_id"),
                app_context["project"],
                app_context["environment"],
                app_context["application_name"],
                control["control_id"],
                control["name"],
                status,
                encode_json(control["framework_refs"]),
                encode_json(control["evidence_event_types"]),
                encode_json(control["required_fields"]),
                encode_json(trace_ids[:_EVIDENCE_TRACE_CAP]),
                evidence_count,
                control["rationale"],
            ),
        )


def event_satisfies_required_fields(event: dict[str, Any], required_fields: list[str]) -> bool:
    attrs = event.get("attributes") or {}
    metadata = as_object(attrs.get("metadata"))
    values: dict[str, Any] = {
        "trace_id": event.get("trace_id"),
        "status": event.get("status"),
        "provider": attrs.get("provider"),
        "model": attrs.get("model"),
        "workflow_name": metadata.get("workflow_name"),
        "application_name": metadata.get("application_name"),
        "user_id": metadata.get("user_id"),
        "retriever": attrs.get("retriever"),
        "document_count": attrs.get("document_count"),
        "tool_name": attrs.get("tool_name"),
        "guardrail_name": attrs.get("guardrail_name"),
        "decision": attrs.get("decision"),
        "matched_rules": attrs.get("matched_rules"),
        "eval_name": attrs.get("eval_name"),
        "score": attrs.get("score"),
        "threshold": attrs.get("threshold"),
        "passed": attrs.get("passed"),
        "agent_name": attrs.get("agent_name"),
        "step_count": attrs.get("step_count"),
        "outcome": attrs.get("outcome"),
        "mode": attrs.get("mode"),
        "fail_open": attrs.get("fail_open"),
        "failed_sends": attrs.get("failed_sends"),
        "prompt.hash": as_object(attrs.get("prompt")).get("hash"),
        "response.hash": as_object(attrs.get("response")).get("hash"),
    }
    return all(values.get(field) not in (None, "", []) for field in required_fields)


def assess_risk_rules(connection, app_context: dict[str, Any], rules: list[dict[str, Any]], events: list[dict[str, Any]]) -> None:
    by_type = {event_type: [event for event in events if event.get("type") == event_type] for event_type in {event.get("type") for event in events}}
    providers = sorted({p for event in by_type.get("model.call", []) if isinstance(p := (event.get("attributes") or {}).get("provider"), str)})
    app_text = " ".join(
        [
            app_context["application_name"],
            " ".join((event.get("attributes") or {}).get("metadata", {}).get("use_case", "") for event in events),
        ]
    ).lower()
    error_events = [event for event in events if event.get("status") == "error"]
    for rule in rules:
        signal = rule["signal"]
        if signal == "provider_dependency" and providers:
            evidence = [event for event in by_type.get("model.call", []) if (event.get("attributes") or {}).get("provider")]
            upsert_rule_finding(connection, app_context, rule, evidence, f"Observed providers: {', '.join(providers)}")
        if signal == "missing_guardrail" and by_type.get("model.call") and not by_type.get("guardrail.decision"):
            upsert_rule_finding(connection, app_context, rule, by_type["model.call"], "Model calls observed without guardrail decision evidence")
        if signal == "missing_eval" and by_type.get("model.call") and not by_type.get("eval.result"):
            upsert_rule_finding(connection, app_context, rule, by_type["model.call"], "Model calls observed without evaluation result evidence")
        if signal == "missing_agent_run" and not by_type.get("agent.run"):
            # primary signal: real tool-call telemetry; secondary: a whole-word
            # agentic term in the app name/use-case
            has_tool_calls = bool(by_type.get("tool.call"))
            text_is_agentic = bool(_AGENTIC_TERMS.search(app_text))
            if has_tool_calls or text_is_agentic:
                reason = (
                    "Tool-call telemetry observed without agent run evidence"
                    if has_tool_calls
                    else "Agentic term in the application name or use-case without agent run evidence"
                )
                upsert_rule_finding(connection, app_context, rule, events, reason)
        if signal == "operational_errors" and error_events:
            upsert_rule_finding(connection, app_context, rule, error_events, f"{len(error_events)} error events observed")
        if signal == "retired_system_telemetry":
            retired_since = _retired_since(connection, app_context)
            if retired_since:
                late = [event for event in events if _after(event.get("timestamp"), retired_since)]
                if late:
                    upsert_rule_finding(
                        connection,
                        app_context,
                        rule,
                        late,
                        f"{len(late)} event(s) observed after the system was retired at {retired_since}",
                    )


def _normalize_ts(value: str | None) -> str:
    """comparable utc timestamp text; the db writes 'YYYY-MM-DD HH:MM:SS' while
    events carry iso-8601, and the two must sort together"""
    if not value:
        return ""
    text = value.strip().replace(" ", "T")
    for suffix in ("Z", "+00:00"):
        text = text.removesuffix(suffix)
    return text


def _after(event_ts: str | None, boundary: str) -> bool:
    return _normalize_ts(event_ts) > _normalize_ts(boundary)


def _retired_since(connection, app_context: dict[str, Any]) -> str | None:
    """when the application's headline lifecycle stage is retired, the time of
    the (latest) retirement record; None otherwise

    mirrors entities.STAGE_ORDER: any intake record whose stage outranks
    retired (in review, approved, recertified, discovered) means the system is
    not considered retired, so telemetry from it is not a violation
    """
    rows = connection.execute(
        """
        SELECT status, updated_at FROM ai_use_cases
        WHERE application_name = :application_name
          AND (
            (:tenant_id IS NULL AND tenant_id IS NULL)
            OR tenant_id = :tenant_id
          )
          AND project = :project AND environment = :environment
        """,
        {
            "application_name": app_context.get("application_name"),
            "tenant_id": app_context.get("tenant_id"),
            "project": app_context.get("project"),
            "environment": app_context.get("environment"),
        },
    ).fetchall()
    if not rows:
        return None
    outranking = {"submitted", "approved", "recertified"}
    if any((row["status"] or "submitted") in outranking for row in rows):
        return None
    retired_rows = [row for row in rows if row["status"] == "retired"]
    if not retired_rows:
        return None
    return max(row["updated_at"] for row in retired_rows)


# --- batch fold: the ingest request path ------------------------------------------

_APP_SCOPE_SQL = (
    "project = :project AND environment = :environment "
    "AND application_name = :application_name "
    "AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)"
)


def _scope_params(app_context: dict[str, Any]) -> dict[str, Any]:
    return {
        "project": app_context["project"],
        "environment": app_context["environment"],
        "application_name": app_context["application_name"],
        "tenant_id": app_context.get("tenant_id"),
    }


def _app_event_stats(connection, app_context: dict[str, Any]) -> tuple[dict[str, int], int, list[str], list[str]]:
    """per-app aggregates over the extracted sdk_events columns

    (counts by event type, total error events, distinct providers, distinct
    use cases) — everything the risk-rule conditions need, with no raw-event
    reads and no decryption; the app-scope composite index serves all four
    """
    params = _scope_params(app_context)
    counts: dict[str, int] = {}
    errors_total = 0
    for row in connection.execute(
        f"SELECT event_type, COUNT(*) AS n, "
        f"SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors "
        f"FROM sdk_events WHERE {_APP_SCOPE_SQL} GROUP BY event_type",
        params,
    ).fetchall():
        counts[row["event_type"]] = int(row["n"])
        errors_total += int(row["errors"] or 0)
    providers = [
        row["provider"]
        for row in connection.execute(
            # model.call only, matching the full evaluator: a provider named on
            # a deployment record is not observed provider *usage*
            f"SELECT DISTINCT provider FROM sdk_events WHERE {_APP_SCOPE_SQL} "
            f"AND event_type = 'model.call' AND provider IS NOT NULL AND provider != '' ORDER BY provider",
            params,
        ).fetchall()
    ]
    use_cases = [
        row["use_case"]
        for row in connection.execute(
            f"SELECT DISTINCT use_case FROM sdk_events WHERE {_APP_SCOPE_SQL} "
            f"AND use_case IS NOT NULL AND use_case != ''",
            params,
        ).fetchall()
    ]
    return counts, errors_total, providers, use_cases


def _recent_trace_ids(
    connection,
    app_context: dict[str, Any],
    *,
    event_type: str | None = None,
    errors_only: bool = False,
    after_timestamp: str | None = None,
) -> list[str]:
    """newest distinct trace ids matching the filter, as bounded evidence"""
    params = _scope_params(app_context)
    clauses = [_APP_SCOPE_SQL]
    if event_type:
        clauses.append("event_type = :event_type")
        params["event_type"] = event_type
    if errors_only:
        clauses.append("status = 'error'")
    if after_timestamp is not None:
        # timestamps are utc everywhere (sdk iso-8601, db 'YYYY-MM-DD HH:MM:SS');
        # normalizing the separator makes them sort together lexicographically
        clauses.append("REPLACE(timestamp, 'T', ' ') > :after_timestamp")
        params["after_timestamp"] = after_timestamp.replace("T", " ")
    rows = connection.execute(
        f"SELECT trace_id FROM sdk_events WHERE {' AND '.join(clauses)} "  # noqa: S608
        f"ORDER BY id DESC LIMIT {_EVIDENCE_TRACE_CAP * 2}",
        params,
    ).fetchall()
    seen: list[str] = []
    for row in rows:
        if row["trace_id"] and row["trace_id"] not in seen:
            seen.append(row["trace_id"])
            if len(seen) >= _EVIDENCE_TRACE_CAP:
                break
    return seen


def _count_after(connection, app_context: dict[str, Any], timestamp: str) -> int:
    params = _scope_params(app_context)
    params["after_timestamp"] = timestamp.replace("T", " ")
    row = connection.execute(
        f"SELECT COUNT(*) AS n FROM sdk_events WHERE {_APP_SCOPE_SQL} "
        f"AND REPLACE(timestamp, 'T', ' ') > :after_timestamp",
        params,
    ).fetchone()
    return int(row["n"])


def _fold_controls(connection, app_context: dict[str, Any], controls: list[dict[str, Any]], batch: list[dict[str, Any]]) -> None:
    """control evidence from the batch alone, persisted monotonically

    evidence needs event attributes, which only exist in (possibly encrypted)
    raw bodies — but the batch is already in memory in plaintext. history only
    grows (retention deliberately keeps derived state), so: qualifying
    evidence in the batch marks the control passing and extends its evidence;
    a batch without evidence leaves an existing assessment exactly as the
    full recompute would have left it; only a control never assessed before
    is written as missing
    """
    for control in controls:
        evidence = [
            event
            for event in batch
            if event.get("type") in control["evidence_event_types"]
            and event_satisfies_required_fields(event, control["required_fields"])
        ]
        existing = connection.execute(
            "SELECT status, evidence_trace_ids, evidence_count FROM control_assessments WHERE assessment_id = ?",
            (_assessment_id(app_context, control),),
        ).fetchone()
        if not evidence:
            if existing is None:
                _write_assessment(connection, app_context, control, "missing", [], 0)
            continue
        prior_ids = decode_json(existing["evidence_trace_ids"], []) if existing else []
        merged = sorted(set(prior_ids) | {event["trace_id"] for event in evidence if event.get("trace_id")})
        prior_count = int(existing["evidence_count"] or 0) if existing else 0
        _write_assessment(connection, app_context, control, "passing", merged, prior_count + len(evidence))


def _assess_rules_from_columns(connection, app_context: dict[str, Any], rules: list[dict[str, Any]]) -> None:
    """risk-rule conditions from column aggregates instead of an event scan

    reproduces assess_risk_rules over full history: findings are create/update
    only (they resolve through human decisions, never automatically), and
    every condition is expressible over the extracted columns
    """
    counts, errors_total, providers, use_cases = _app_event_stats(connection, app_context)
    app_text = " ".join([app_context["application_name"], *use_cases]).lower()
    for rule in rules:
        signal = rule["signal"]
        if signal == "provider_dependency" and providers:
            write_rule_finding(
                connection,
                app_context,
                rule,
                _recent_trace_ids(connection, app_context, event_type="model.call"),
                f"Observed providers: {', '.join(providers)}",
            )
        if signal == "missing_guardrail" and counts.get("model.call") and not counts.get("guardrail.decision"):
            write_rule_finding(
                connection,
                app_context,
                rule,
                _recent_trace_ids(connection, app_context, event_type="model.call"),
                "Model calls observed without guardrail decision evidence",
            )
        if signal == "missing_eval" and counts.get("model.call") and not counts.get("eval.result"):
            write_rule_finding(
                connection,
                app_context,
                rule,
                _recent_trace_ids(connection, app_context, event_type="model.call"),
                "Model calls observed without evaluation result evidence",
            )
        if signal == "missing_agent_run" and not counts.get("agent.run"):
            has_tool_calls = bool(counts.get("tool.call"))
            text_is_agentic = bool(_AGENTIC_TERMS.search(app_text))
            if has_tool_calls or text_is_agentic:
                reason = (
                    "Tool-call telemetry observed without agent run evidence"
                    if has_tool_calls
                    else "Agentic term in the application name or use-case without agent run evidence"
                )
                write_rule_finding(
                    connection, app_context, rule, _recent_trace_ids(connection, app_context), reason
                )
        if signal == "operational_errors" and errors_total:
            write_rule_finding(
                connection,
                app_context,
                rule,
                _recent_trace_ids(connection, app_context, errors_only=True),
                f"{errors_total} error events observed",
            )
        if signal == "retired_system_telemetry":
            retired_since = _retired_since(connection, app_context)
            if retired_since:
                late_count = _count_after(connection, app_context, retired_since)
                if late_count:
                    write_rule_finding(
                        connection,
                        app_context,
                        rule,
                        _recent_trace_ids(connection, app_context, after_timestamp=retired_since),
                        f"{late_count} event(s) observed after the system was retired at {retired_since}",
                    )


def fold_batch_assessments(events: list[dict[str, Any]]) -> None:
    """assess controls and risk rules for one ingested batch

    the request-path replacement for refresh_governance_assessments: costs
    O(batch) plus a few indexed aggregates per touched application, instead of
    reading and decrypting each application's entire event history. the full
    refresh stays for rebuilds
    """
    from .lifecycle import application_is_registered, events_by_app_scope

    with connect() as connection:
        controls_by_tenant: dict[str, list[dict[str, Any]]] = {}
        rules_by_tenant: dict[str, list[dict[str, Any]]] = {}
        for app_context, batch in events_by_app_scope(events):
            if not application_is_registered(connection, app_context):
                continue
            tid = app_context.get("tenant_id") or ""
            if tid not in controls_by_tenant:
                controls_by_tenant[tid] = list_control_library(connection, tid)
                rules_by_tenant[tid] = list_risk_rules(connection, tid)
            _fold_controls(connection, app_context, controls_by_tenant[tid], batch)
            _assess_rules_from_columns(connection, app_context, rules_by_tenant[tid])


def upsert_rule_finding(
    connection,
    app_context: dict[str, Any],
    rule: dict[str, Any],
    evidence_events: list[dict[str, Any]],
    evidence_summary: str,
) -> None:
    trace_ids = sorted({event["trace_id"] for event in evidence_events if event.get("trace_id")})
    write_rule_finding(connection, app_context, rule, trace_ids, evidence_summary)


def write_rule_finding(
    connection,
    app_context: dict[str, Any],
    rule: dict[str, Any],
    trace_ids: list[str],
    evidence_summary: str,
) -> None:
    trace_ids = trace_ids[:_EVIDENCE_TRACE_CAP]
    finding_id = entity_id(
        "risk-finding",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        rule["rule_id"],
    )
    # a reviewer's decision (accepted, mitigation_required, ...) survives
    # recompute instead of being reset to "open"
    status = _preserve_decided_status(
        connection, "risk_findings", "finding_id", finding_id, "open", {"open"}
    )
    connection.execute(
        """
        INSERT OR REPLACE INTO risk_findings (
            finding_id, tenant_id, project, environment, application_name, rule_id, risk, severity,
            status, rationale, framework_refs, evidence_trace_ids, evidence_summary, evaluated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (
            finding_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            rule["rule_id"],
            rule["name"],
            rule["severity"],
            status,
            rule["rationale"],
            encode_json(rule["framework_refs"]),
            encode_json(trace_ids),
            evidence_summary,
        ),
    )


def upsert_control_definition(control: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """create or update a control override for one tenant; platform defaults
    (tenant_id '') are immutable here, writes land under the tenant's own id"""
    if not tenant_id:
        raise ValueError("a tenant_id is required to customize the control library")
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO control_library (
                tenant_id, control_id, name, framework_refs, evidence_event_types, required_fields, rationale
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, control_id) DO UPDATE SET
                name=excluded.name, framework_refs=excluded.framework_refs,
                evidence_event_types=excluded.evidence_event_types,
                required_fields=excluded.required_fields, rationale=excluded.rationale
            """,
            (
                tenant_id,
                control["control_id"],
                control["name"],
                encode_json(control["framework_refs"]),
                encode_json(control["evidence_event_types"]),
                encode_json(control["required_fields"]),
                control["rationale"],
            ),
        )
    return {**control, "tenant_id": tenant_id}


def upsert_risk_rule(rule: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    if rule["signal"] not in SUPPORTED_RISK_SIGNALS:
        raise ValueError(f"unsupported risk signal: {rule['signal']}")
    if not tenant_id:
        raise ValueError("a tenant_id is required to customize risk rules")
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO risk_rules (
                tenant_id, rule_id, name, signal, severity, framework_refs, rationale
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
                name=excluded.name, signal=excluded.signal, severity=excluded.severity,
                framework_refs=excluded.framework_refs, rationale=excluded.rationale
            """,
            (
                tenant_id,
                rule["rule_id"],
                rule["name"],
                rule["signal"],
                rule["severity"],
                encode_json(rule["framework_refs"]),
                rule["rationale"],
            ),
        )
    return {**rule, "tenant_id": tenant_id}


def scoped_policy_rows(table: str, *, tenant_id: str | None, project: str | None, environment: str | None) -> list[dict[str, Any]]:
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
        rows = connection.execute(f"SELECT * FROM {table} {where} ORDER BY application_name, evaluated_at DESC", params).fetchall()
    return [dict(row) for row in rows]


def list_control_assessments(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "framework_refs": decode_json(row["framework_refs"], []),
            "evidence_event_types": decode_json(row["evidence_event_types"], []),
            "required_fields": decode_json(row["required_fields"], []),
            "evidence_trace_ids": decode_json(row["evidence_trace_ids"], []),
        }
        for row in scoped_policy_rows("control_assessments", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_risk_findings(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "framework_refs": decode_json(row["framework_refs"], []),
            "evidence_trace_ids": decode_json(row["evidence_trace_ids"], []),
        }
        for row in scoped_policy_rows("risk_findings", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_controls_catalog(tenant_id: str | None = None) -> list[dict[str, Any]]:
    with connect() as connection:
        return list_control_library(connection, tenant_id)


def list_configured_risk_rules(tenant_id: str | None = None) -> list[dict[str, Any]]:
    with connect() as connection:
        return list_risk_rules(connection, tenant_id)

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from .raw_events import connect


def entity_id(*parts: Any) -> str:
    encoded = "|".join("" if part is None else str(part) for part in parts).encode("utf-8")
    return sha256(encoded).hexdigest()


def encode_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def decode_json(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def init_entities() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_applications (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                use_cases TEXT NOT NULL,
                model_purposes TEXT NOT NULL,
                providers TEXT NOT NULL,
                models TEXT NOT NULL,
                model_calls INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_workflows (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                applications TEXT NOT NULL,
                providers TEXT NOT NULL,
                models TEXT NOT NULL,
                model_calls INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_models (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                operations TEXT NOT NULL,
                applications TEXT NOT NULL,
                model_calls INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_providers (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                provider TEXT NOT NULL,
                models TEXT NOT NULL,
                applications TEXT NOT NULL,
                model_calls INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_observed_events (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT,
                workflow_name TEXT,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                duration_ms REAL,
                attributes TEXT NOT NULL,
                observed_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_risks (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                risk TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT NOT NULL,
                evidence_trace_ids TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_controls (
                entity_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                control TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence TEXT NOT NULL,
                evidence_event_type TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        for table in (
            "governance_applications",
            "governance_workflows",
            "governance_models",
            "governance_providers",
            "governance_observed_events",
            "governance_risks",
            "governance_controls",
        ):
            connection.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_scope ON {table}(tenant_id, project, environment)")


def process_events(events: list[dict[str, Any]]) -> None:
    # Entity upserts are read-modify-write on JSON set columns (fetch_one +
    # merge_sets + ON CONFLICT). Under concurrent ingest, two batches could each
    # read the old set and the second write would clobber the first, dropping a
    # provider/model from the inventory (audit H-11). Run the whole batch inside
    # an IMMEDIATE transaction so a second concurrent ingest waits for the write
    # lock (up to busy_timeout) and then reads the committed state — making the
    # merge safe. SQLite is single-writer regardless, so this adds no throughput
    # cost beyond what the engine already imposes.
    connection = connect()
    connection.isolation_level = None
    try:
        connection.execute("BEGIN IMMEDIATE")
        for event in events:
            process_event(connection, event)
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def process_event(connection, event: dict[str, Any]) -> None:
    event_type = event["type"]
    attrs = event.get("attributes") or {}
    metadata = attrs.get("metadata") or {}
    usage = attrs.get("usage") or {}

    if event_type == "model.call":
        upsert_application(connection, event, attrs, metadata, usage)
        upsert_workflow(connection, event, attrs, metadata, usage)
        upsert_model(connection, event, attrs, metadata, usage)
        upsert_provider(connection, event, attrs, metadata)
        upsert_model_risks(connection, event, attrs, metadata, usage)
        upsert_control(connection, event, metadata, "Provider and model usage is inventoried", "model.call")

    if event_type == "trace.completed":
        upsert_control(connection, event, metadata, "Workflow traces are captured", "trace.completed")

    if event_type == "sdk.health":
        upsert_control(connection, event, metadata, "SDK fail-open health is visible", "sdk.health")

    if event_type in {"retrieval.call", "tool.call", "guardrail.decision", "eval.result", "agent.run"}:
        upsert_observed_event(connection, event, attrs, metadata)
        control_name = {
            "retrieval.call": "Retrieval evidence is captured",
            "tool.call": "Tool execution evidence is captured",
            "guardrail.decision": "Guardrail decisions are captured",
            "eval.result": "Evaluation results are captured",
            "agent.run": "Agent run evidence is captured",
        }[event_type]
        upsert_control(connection, event, metadata, control_name, event_type)

    if event_type == "guardrail.decision":
        upsert_guardrail_risk(connection, event, attrs, metadata)

    if event_type == "eval.result":
        upsert_eval_risk(connection, event, attrs, metadata)


def upsert_application(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any], usage: dict[str, Any]) -> None:
    application_name = metadata.get("application_name")
    if not application_name:
        return
    key = entity_id("application", metadata.get("tenant_id"), event["project"], event["environment"], application_name)
    row = fetch_one(connection, "governance_applications", key)
    values = merge_sets(
        row,
        {
            "use_cases": metadata.get("use_case"),
            "model_purposes": metadata.get("model_purpose"),
            "providers": attrs.get("provider"),
            "models": attrs.get("model"),
        },
    )
    connection.execute(
        """
        INSERT INTO governance_applications (
            entity_id, tenant_id, project, environment, application_name, use_cases, model_purposes,
            providers, models, model_calls, errors, input_tokens, output_tokens, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            use_cases=excluded.use_cases,
            model_purposes=excluded.model_purposes,
            providers=excluded.providers,
            models=excluded.models,
            model_calls=governance_applications.model_calls + 1,
            errors=governance_applications.errors + excluded.errors,
            input_tokens=governance_applications.input_tokens + excluded.input_tokens,
            output_tokens=governance_applications.output_tokens + excluded.output_tokens,
            last_seen=excluded.last_seen
        """,
        (
            key,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            application_name,
            encode_json(values["use_cases"]),
            encode_json(values["model_purposes"]),
            encode_json(values["providers"]),
            encode_json(values["models"]),
            1,
            1 if event.get("status") == "error" else 0,
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            event["timestamp"],
            event["timestamp"],
        ),
    )


def upsert_workflow(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any], usage: dict[str, Any]) -> None:
    workflow_name = metadata.get("workflow_name") or event.get("name") or "unknown"
    key = entity_id("workflow", metadata.get("tenant_id"), event["project"], event["environment"], workflow_name)
    row = fetch_one(connection, "governance_workflows", key)
    values = merge_sets(
        row,
        {
            "applications": metadata.get("application_name"),
            "providers": attrs.get("provider"),
            "models": attrs.get("model"),
        },
    )
    connection.execute(
        """
        INSERT INTO governance_workflows (
            entity_id, tenant_id, project, environment, workflow_name, applications, providers, models,
            model_calls, errors, input_tokens, output_tokens, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            applications=excluded.applications,
            providers=excluded.providers,
            models=excluded.models,
            model_calls=governance_workflows.model_calls + 1,
            errors=governance_workflows.errors + excluded.errors,
            input_tokens=governance_workflows.input_tokens + excluded.input_tokens,
            output_tokens=governance_workflows.output_tokens + excluded.output_tokens,
            last_seen=excluded.last_seen
        """,
        (
            key,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            workflow_name,
            encode_json(values["applications"]),
            encode_json(values["providers"]),
            encode_json(values["models"]),
            1,
            1 if event.get("status") == "error" else 0,
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            event["timestamp"],
            event["timestamp"],
        ),
    )


def upsert_model(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any], usage: dict[str, Any]) -> None:
    provider = attrs.get("provider") or "unknown"
    model = attrs.get("model") or "unknown"
    key = entity_id("model", metadata.get("tenant_id"), event["project"], event["environment"], provider, model)
    row = fetch_one(connection, "governance_models", key)
    values = merge_sets(row, {"operations": attrs.get("operation"), "applications": metadata.get("application_name")})
    connection.execute(
        """
        INSERT INTO governance_models (
            entity_id, tenant_id, project, environment, provider, model, operations, applications,
            model_calls, errors, input_tokens, output_tokens, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            operations=excluded.operations,
            applications=excluded.applications,
            model_calls=governance_models.model_calls + 1,
            errors=governance_models.errors + excluded.errors,
            input_tokens=governance_models.input_tokens + excluded.input_tokens,
            output_tokens=governance_models.output_tokens + excluded.output_tokens,
            last_seen=excluded.last_seen
        """,
        (
            key,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            provider,
            model,
            encode_json(values["operations"]),
            encode_json(values["applications"]),
            1,
            1 if event.get("status") == "error" else 0,
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            event["timestamp"],
            event["timestamp"],
        ),
    )


def upsert_provider(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any]) -> None:
    provider = attrs.get("provider")
    if not provider:
        return
    key = entity_id("provider", metadata.get("tenant_id"), event["project"], event["environment"], provider)
    row = fetch_one(connection, "governance_providers", key)
    values = merge_sets(row, {"models": attrs.get("model"), "applications": metadata.get("application_name")})
    connection.execute(
        """
        INSERT INTO governance_providers (
            entity_id, tenant_id, project, environment, provider, models, applications,
            model_calls, errors, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            models=excluded.models,
            applications=excluded.applications,
            model_calls=governance_providers.model_calls + 1,
            errors=governance_providers.errors + excluded.errors,
            last_seen=excluded.last_seen
        """,
        (
            key,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            provider,
            encode_json(values["models"]),
            encode_json(values["applications"]),
            1,
            1 if event.get("status") == "error" else 0,
            event["timestamp"],
            event["timestamp"],
        ),
    )


def upsert_observed_event(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any]) -> None:
    name = (
        attrs.get("retriever")
        or attrs.get("tool_name")
        or attrs.get("guardrail_name")
        or attrs.get("eval_name")
        or attrs.get("agent_name")
        or event.get("name")
        or "unknown"
    )
    key = entity_id(event["type"], metadata.get("tenant_id") or "", event["project"], event["environment"], event["trace_id"], event["span_id"], name)
    connection.execute(
        """
        INSERT OR REPLACE INTO governance_observed_events (
            entity_id, entity_type, tenant_id, project, environment, application_name, workflow_name,
            name, status, trace_id, duration_ms, attributes, observed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            key,
            event["type"],
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            metadata.get("application_name"),
            metadata.get("workflow_name"),
            name,
            event.get("status", "success"),
            event["trace_id"],
            event.get("duration_ms"),
            encode_json(attrs),
            event["timestamp"],
        ),
    )


def upsert_model_risks(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any], usage: dict[str, Any]) -> None:
    application_name = metadata.get("application_name")
    if not application_name:
        return
    provider = attrs.get("provider")
    if provider:
        upsert_risk(
            connection,
            event,
            metadata,
            risk="Third-party AI dependency",
            severity="Medium",
            confidence=0.8,
            evidence=f"Observed provider: {provider}",
            source="model.call",
        )
    if event.get("status") == "error":
        upsert_risk(
            connection,
            event,
            metadata,
            risk="Operational reliability failures",
            severity="High",
            confidence=0.9,
            evidence="Failed model call observed",
            source="model.call",
        )
    if int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0) > 1000:
        upsert_risk(
            connection,
            event,
            metadata,
            risk="High-volume model usage",
            severity="Medium",
            confidence=0.7,
            evidence="Single model call exceeded 1000 total tokens",
            source="model.call",
        )
    use_case = str(metadata.get("use_case") or "")
    if any(term in use_case.lower() for term in ("claim", "insurance", "customer", "support")):
        upsert_risk(
            connection,
            event,
            metadata,
            risk="Potential sensitive business process",
            severity="Medium",
            confidence=0.7,
            evidence=f"Observed use case: {use_case}",
            source="model.call",
        )


def upsert_guardrail_risk(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any]) -> None:
    if attrs.get("decision") in {"warn", "block"}:
        upsert_risk(
            connection,
            event,
            metadata,
            risk="Guardrail warning",
            severity="High" if attrs.get("decision") == "block" else "Medium",
            confidence=0.85,
            evidence=f"{attrs.get('guardrail_name', event.get('name'))} decision: {attrs.get('decision')}",
            source="guardrail.decision",
        )


def upsert_eval_risk(connection, event: dict[str, Any], attrs: dict[str, Any], metadata: dict[str, Any]) -> None:
    if attrs.get("passed") is False:
        upsert_risk(
            connection,
            event,
            metadata,
            risk="Evaluation failed",
            severity="High",
            confidence=0.9,
            evidence=f"{attrs.get('eval_name', event.get('name'))} scored {attrs.get('score')} below {attrs.get('threshold')}",
            source="eval.result",
        )


def upsert_risk(
    connection,
    event: dict[str, Any],
    metadata: dict[str, Any],
    *,
    risk: str,
    severity: str,
    confidence: float,
    evidence: str,
    source: str,
) -> None:
    application_name = metadata.get("application_name") or "unknown"
    key = entity_id("risk", metadata.get("tenant_id"), event["project"], event["environment"], application_name, risk, source)
    row = fetch_one(connection, "governance_risks", key)
    trace_ids = set(decode_json(row["evidence_trace_ids"], []) if row else [])
    trace_ids.add(event["trace_id"])
    connection.execute(
        """
        INSERT INTO governance_risks (
            entity_id, tenant_id, project, environment, application_name, risk, severity, confidence,
            evidence, evidence_trace_ids, status, source, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            severity=excluded.severity,
            confidence=excluded.confidence,
            evidence=excluded.evidence,
            evidence_trace_ids=excluded.evidence_trace_ids,
            status=excluded.status,
            last_seen=excluded.last_seen
        """,
        (
            key,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            application_name,
            risk,
            severity,
            confidence,
            evidence,
            encode_json(sorted(trace_ids)),
            "open",
            source,
            event["timestamp"],
            event["timestamp"],
        ),
    )


def upsert_control(connection, event: dict[str, Any], metadata: dict[str, Any], control: str, evidence_event_type: str) -> None:
    key = entity_id("control", metadata.get("tenant_id"), event["project"], event["environment"], control)
    row = fetch_one(connection, "governance_controls", key)
    count = int(row["evidence_count"]) + 1 if row else 1
    connection.execute(
        """
        INSERT INTO governance_controls (
            entity_id, tenant_id, project, environment, control, status, evidence,
            evidence_event_type, evidence_count, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
            status=excluded.status,
            evidence=excluded.evidence,
            evidence_event_type=excluded.evidence_event_type,
            evidence_count=excluded.evidence_count,
            last_seen=excluded.last_seen
        """,
        (
            key,
            metadata.get("tenant_id"),
            event["project"],
            event["environment"],
            control,
            "passing",
            f"{count} {evidence_event_type} events recorded",
            evidence_event_type,
            count,
            event["timestamp"],
            event["timestamp"],
        ),
    )


def fetch_one(connection, table: str, key: str):
    return connection.execute(f"SELECT * FROM {table} WHERE entity_id = ?", (key,)).fetchone()


def merge_sets(row, values: dict[str, Any]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for field, value in values.items():
        existing = set(decode_json(row[field], []) if row else [])
        if value:
            existing.add(str(value))
        merged[field] = sorted(existing)
    return merged


def scoped_rows(table: str, *, tenant_id: str | None, project: str | None, environment: str | None, order_by: str = "last_seen") -> list[dict[str, Any]]:
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
        rows = connection.execute(f"SELECT * FROM {table} {where} ORDER BY {order_by} DESC", params).fetchall()
    return [dict(row) for row in rows]


STAGE_ORDER = ["retired", "rejected", "approved", "recertified", "in_review", "discovered"]


def _lifecycle_by_application(tenant_id: str | None, project: str | None, environment: str | None) -> dict[str, dict[str, Any]]:
    """Governance stage per application, derived from its intake record(s):
    none -> discovered (seen in telemetry, never registered); submitted ->
    in_review; approved/recertified/rejected/retired as decided. Also the
    highest risk tier declared for it."""
    rows = scoped_rows("ai_use_cases", tenant_id=tenant_id, project=project, environment=environment, order_by="updated_at")
    out: dict[str, dict[str, Any]] = {}
    tier_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for row in rows:
        name = row.get("application_name")
        if not name:
            continue
        status = row.get("status") or "submitted"
        stage = "in_review" if status == "submitted" else status
        current = out.get(name)
        tier = row.get("risk_tier")
        if current is None:
            out[name] = {"stage": stage, "risk_tier": tier, "intake_ids": [row["intake_id"]]}
            continue
        current["intake_ids"].append(row["intake_id"])
        # An in-review or approved record outranks retired/rejected for the headline stage.
        if STAGE_ORDER.index(stage) > STAGE_ORDER.index(current["stage"]):
            current["stage"] = stage
        if tier_rank.get(str(tier), -1) > tier_rank.get(str(current["risk_tier"]), -1):
            current["risk_tier"] = tier
    return out


def list_applications(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    lifecycle = _lifecycle_by_application(tenant_id, project, environment)
    return [
        {
            **row,
            "use_cases": decode_json(row["use_cases"], []),
            "model_purposes": decode_json(row["model_purposes"], []),
            "providers": decode_json(row["providers"], []),
            "models": decode_json(row["models"], []),
            "stage": lifecycle.get(row["application_name"], {}).get("stage", "discovered"),
            "risk_tier": lifecycle.get(row["application_name"], {}).get("risk_tier"),
            "intake_ids": lifecycle.get(row["application_name"], {}).get("intake_ids", []),
        }
        for row in scoped_rows("governance_applications", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_workflows(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "applications": decode_json(row["applications"], []),
            "providers": decode_json(row["providers"], []),
            "models": decode_json(row["models"], []),
        }
        for row in scoped_rows("governance_workflows", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_models(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "operations": decode_json(row["operations"], []),
            "applications": decode_json(row["applications"], []),
        }
        for row in scoped_rows("governance_models", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_providers(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "models": decode_json(row["models"], []),
            "applications": decode_json(row["applications"], []),
        }
        for row in scoped_rows("governance_providers", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_observed_events(entity_type: str, *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    rows = scoped_rows("governance_observed_events", tenant_id=tenant_id, project=project, environment=environment, order_by="observed_at")
    return [
        {**row, "attributes": decode_json(row["attributes"], {})}
        for row in rows
        if row["entity_type"] == entity_type
    ]


def list_risks(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return [
        {**row, "evidence_trace_ids": decode_json(row["evidence_trace_ids"], [])}
        for row in scoped_rows("governance_risks", tenant_id=tenant_id, project=project, environment=environment)
    ]


def list_controls(*, tenant_id: str | None = None, project: str | None = None, environment: str | None = None) -> list[dict[str, Any]]:
    return scoped_rows("governance_controls", tenant_id=tenant_id, project=project, environment=environment)


def tenant_application_stats() -> dict[str, dict[str, Any]]:
    """Per-tenant application count and most recent activity, for the platform
    tenant overview. This is operational metadata (counts and timestamps), not
    governance content."""
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT tenant_id, COUNT(*) AS app_count, MAX(last_seen) AS last_activity
            FROM governance_applications
            WHERE tenant_id IS NOT NULL
            GROUP BY tenant_id
            """
        ).fetchall()
    return {row["tenant_id"]: {"app_count": int(row["app_count"]), "last_activity": row["last_activity"]} for row in rows}

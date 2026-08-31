# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from hashlib import sha256
from typing import Any

from .entities import as_object, decode_json, encode_json, entity_id
from .raw_events import connect, deserialize_raw_event
from .scoping import count_scoped_rows, scoped_rows

MATERIAL_FIELDS = {
    "agents",
    "eval_thresholds",
    "evals",
    "guardrails",
    "models",
    "providers",
    "retrievers",
    "tools",
    "workflows",
}

HIGH_RISK_FIELDS = {"eval_thresholds", "guardrails", "models", "providers", "tools"}


def init_lifecycle() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS lifecycle_fingerprints (
                fingerprint_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                fingerprint_payload TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS change_events (
                change_id TEXT PRIMARY KEY,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_name TEXT NOT NULL,
                change_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                previous_hash TEXT,
                current_hash TEXT NOT NULL,
                previous_payload TEXT,
                current_payload TEXT NOT NULL,
                changed_fields TEXT NOT NULL,
                evidence_trace_ids TEXT NOT NULL,
                rationale TEXT NOT NULL,
                detected_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_tasks (
                task_id TEXT PRIMARY KEY,
                change_id TEXT NOT NULL,
                tenant_id TEXT,
                project TEXT NOT NULL,
                environment TEXT NOT NULL,
                application_name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                title TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_lifecycle_fingerprints_scope ON lifecycle_fingerprints(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_change_events_scope ON change_events(tenant_id, project, environment)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_review_tasks_scope ON review_tasks(tenant_id, project, environment)")


def refresh_lifecycle_state(scopes: list[dict[str, Any]] | None = None) -> None:
    """recompute change fingerprints from full history; scopes limits to the
    apps an ingest touched, None does everything

    this is the rebuild path. the ingest request path uses
    fold_batch_fingerprints instead, which costs O(batch) — this one reads and
    (when encryption is on) decrypts every stored event for each app
    """
    with connect() as connection:
        applications = _applications_in_scope(connection, scopes)
        for application in applications:
            app_context = dict(application)
            events = list_application_events(connection, app_context)
            for fingerprint in build_fingerprints(app_context, events):
                upsert_fingerprint(connection, app_context, fingerprint)


def events_by_app_scope(events: list[dict[str, Any]]) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """group a batch by the (tenant, project, environment, application) it
    belongs to; events with no application_name carry no derived state"""
    groups: dict[tuple, tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    for event in events:
        metadata = as_object(as_object(event.get("attributes")).get("metadata"))
        application_name = metadata.get("application_name")
        if not application_name:
            continue
        key = (metadata.get("tenant_id"), event.get("project"), event.get("environment"), application_name)
        if key not in groups:
            groups[key] = (
                {
                    "tenant_id": key[0],
                    "project": key[1],
                    "environment": key[2],
                    "application_name": application_name,
                },
                [],
            )
        groups[key][1].append(event)
    return list(groups.values())


def application_is_registered(connection, app_context: dict[str, Any]) -> bool:
    """whether this scope exists in governance_applications

    the full refresh paths iterate governance_applications (populated by
    model.call telemetry), so an app known only from prompt/deployment/eval
    metadata carries no fingerprints or assessments; the fold paths must draw
    the same line or a metadata-only app suddenly grows blocking state
    """
    row = connection.execute(
        """
        SELECT 1 FROM governance_applications
        WHERE project = :project AND environment = :environment
          AND application_name = :application_name
          AND ((:tenant_id IS NULL AND tenant_id IS NULL) OR tenant_id = :tenant_id)
        LIMIT 1
        """,
        {
            "project": app_context["project"],
            "environment": app_context["environment"],
            "application_name": app_context["application_name"],
            "tenant_id": app_context.get("tenant_id"),
        },
    ).fetchone()
    return row is not None


def _merge_payload(stored: dict[str, Any], fresh: dict[str, Any]) -> dict[str, Any]:
    """monotone union of fingerprint payloads (each key is a sorted label list)"""
    return {
        key: sorted(set(stored.get(key) or []) | set(fresh.get(key) or []))
        for key in set(stored) | set(fresh)
    }


def fold_batch_fingerprints(events: list[dict[str, Any]]) -> None:
    """fold one ingested batch into the stored fingerprints

    the request-path replacement for refresh_lifecycle_state: fingerprint
    payloads are monotone label sets and retention deliberately keeps derived
    state, so union(stored payload, payload(batch)) equals what a full
    recompute over all history would produce — at O(batch) cost, with no
    raw-event reads and no decryption. change detection is unchanged because
    the merged payload goes through the same upsert_fingerprint hashing; the
    change event's evidence trace ids are the batch's (the events that caused
    the change), where the full path attached all of history's
    """
    with connect() as connection:
        for app_context, batch in events_by_app_scope(events):
            if not application_is_registered(connection, app_context):
                continue
            for fingerprint in build_fingerprints(app_context, batch):
                row = connection.execute(
                    "SELECT fingerprint_payload, last_seen FROM lifecycle_fingerprints WHERE fingerprint_id = ?",
                    (_fingerprint_id(app_context, fingerprint["subject_type"], fingerprint["subject_name"]),),
                ).fetchone()
                if row is not None:
                    fingerprint["payload"] = _merge_payload(
                        decode_json(row["fingerprint_payload"], {}), fingerprint["payload"]
                    )
                    fingerprint["observed_at"] = max(row["last_seen"] or "", fingerprint["observed_at"] or "")
                upsert_fingerprint(connection, app_context, fingerprint)


def _applications_in_scope(connection, scopes: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT DISTINCT tenant_id, project, environment, application_name FROM governance_applications"
    ).fetchall()
    if scopes is None:
        return [dict(row) for row in rows]
    wanted = {(s.get("tenant_id"), s["project"], s["environment"], s["application_name"]) for s in scopes}
    return [
        dict(row)
        for row in rows
        if (row["tenant_id"], row["project"], row["environment"], row["application_name"]) in wanted
    ]


def list_application_events(connection, app_context: dict[str, Any]) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT raw_event FROM sdk_events
        WHERE project = :project
          AND environment = :environment
          AND application_name = :application_name
          AND (
            (:tenant_id IS NULL AND tenant_id IS NULL)
            OR tenant_id = :tenant_id
          )
        ORDER BY id
        """,
        app_context,
    ).fetchall()
    # deserialize_raw_event decrypts when NORINTH_ENCRYPT_RAW_EVENTS=1 and passes
    # plaintext through otherwise; a plain json decode would silently yield {} for
    # every encrypted row, disabling material-change detection
    return [deserialize_raw_event(row["raw_event"]) for row in rows]


def build_fingerprints(app_context: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    app_payload = fingerprint_payload(events)
    fingerprints = [
        {
            "subject_type": "application",
            "subject_name": app_context["application_name"],
            "payload": app_payload,
            "trace_ids": trace_ids(events),
            "observed_at": latest_timestamp(events),
        }
    ]
    for workflow_name in sorted(app_payload["workflows"]):
        workflow_events = [
            event
            for event in events
            if as_object(as_object(event.get("attributes")).get("metadata")).get("workflow_name") == workflow_name
        ]
        fingerprints.append(
            {
                "subject_type": "workflow",
                "subject_name": workflow_name,
                "payload": fingerprint_payload(workflow_events),
                "trace_ids": trace_ids(workflow_events),
                "observed_at": latest_timestamp(workflow_events),
            }
        )
    return fingerprints


def fingerprint_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agents": sorted(attribute_values(events, "agent_name")),
        # payload entries are sets of labels; without the dedup a second call
        # of an already-known model appended a duplicate, so ordinary repeat
        # usage read as a material change
        "eval_thresholds": sorted(
            {
                f"{attrs.get('eval_name')}:{attrs.get('threshold')}"
                for attrs in event_attributes_for_type(events, "eval.result")
                if attrs.get("eval_name") and attrs.get("threshold") is not None
            }
        ),
        "evals": sorted(attribute_values(events, "eval_name")),
        "guardrails": sorted(attribute_values(events, "guardrail_name")),
        "models": sorted(
            {
                f"{attrs.get('provider')}:{attrs.get('model')}"
                for attrs in event_attributes_for_type(events, "model.call")
                if attrs.get("provider") and attrs.get("model")
            }
        ),
        "providers": sorted(attribute_values(events, "provider")),
        "retrievers": sorted(attribute_values(events, "retriever")),
        "tools": sorted(attribute_values(events, "tool_name")),
        "workflows": sorted(metadata_values(events, "workflow_name")),
    }


def event_attributes_for_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [event.get("attributes") or {} for event in events if event.get("type") == event_type]


def attribute_values(events: list[dict[str, Any]], field: str) -> set[str]:
    values = set()
    for event in events:
        value = (event.get("attributes") or {}).get(field)
        if value not in (None, ""):
            values.add(str(value))
    return values


def metadata_values(events: list[dict[str, Any]], field: str) -> set[str]:
    values = set()
    for event in events:
        metadata = as_object(as_object(event.get("attributes")).get("metadata"))
        value = metadata.get(field)
        if value not in (None, ""):
            values.add(str(value))
    return values


def trace_ids(events: list[dict[str, Any]]) -> list[str]:
    return sorted({event["trace_id"] for event in events if event.get("trace_id")})


def latest_timestamp(events: list[dict[str, Any]]) -> str:
    return max((event["timestamp"] for event in events if event.get("timestamp")), default="")


def hash_payload(payload: dict[str, Any]) -> str:
    return sha256(encode_json(payload).encode("utf-8")).hexdigest()


def _fingerprint_id(app_context: dict[str, Any], subject_type: str, subject_name: str) -> str:
    return entity_id(
        "lifecycle-fingerprint",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        subject_type,
        subject_name,
    )


def upsert_fingerprint(connection, app_context: dict[str, Any], fingerprint: dict[str, Any]) -> None:
    fingerprint_hash = hash_payload(fingerprint["payload"])
    fingerprint_id = _fingerprint_id(app_context, fingerprint["subject_type"], fingerprint["subject_name"])
    existing = connection.execute(
        "SELECT * FROM lifecycle_fingerprints WHERE fingerprint_id = ?",
        (fingerprint_id,),
    ).fetchone()
    if existing and existing["fingerprint_hash"] != fingerprint_hash:
        previous_payload = decode_json(existing["fingerprint_payload"], {})
        changed_fields = changed_material_fields(previous_payload, fingerprint["payload"])
        if changed_fields:
            insert_change_event(
                connection,
                app_context,
                fingerprint,
                previous_hash=existing["fingerprint_hash"],
                current_hash=fingerprint_hash,
                previous_payload=previous_payload,
                changed_fields=changed_fields,
            )
    observed_at = fingerprint["observed_at"]
    connection.execute(
        """
        INSERT INTO lifecycle_fingerprints (
            fingerprint_id, tenant_id, project, environment, application_name, subject_type,
            subject_name, fingerprint_hash, fingerprint_payload, first_seen, last_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint_id) DO UPDATE SET
            fingerprint_hash=excluded.fingerprint_hash,
            fingerprint_payload=excluded.fingerprint_payload,
            last_seen=excluded.last_seen
        """,
        (
            fingerprint_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            fingerprint["subject_type"],
            fingerprint["subject_name"],
            fingerprint_hash,
            encode_json(fingerprint["payload"]),
            observed_at,
            observed_at,
        ),
    )


def changed_material_fields(previous_payload: dict[str, Any], current_payload: dict[str, Any]) -> list[str]:
    # compare as sets: the payload entries are label sets, and rows written
    # before the dedup fix may still carry duplicate entries — a list compare
    # would report a phantom change on the first recompute after upgrade
    return sorted(
        field
        for field in MATERIAL_FIELDS
        if set(previous_payload.get(field) or []) != set(current_payload.get(field) or [])
    )


def insert_change_event(
    connection,
    app_context: dict[str, Any],
    fingerprint: dict[str, Any],
    *,
    previous_hash: str,
    current_hash: str,
    previous_payload: dict[str, Any],
    changed_fields: list[str],
) -> None:
    change_id = entity_id(
        "change-event",
        app_context.get("tenant_id"),
        app_context["project"],
        app_context["environment"],
        app_context["application_name"],
        fingerprint["subject_type"],
        fingerprint["subject_name"],
        previous_hash,
        current_hash,
    )
    severity = "High" if HIGH_RISK_FIELDS.intersection(changed_fields) else "Medium"
    rationale = f"Material {fingerprint['subject_type']} change detected in: {', '.join(changed_fields)}"
    connection.execute(
        """
        INSERT OR IGNORE INTO change_events (
            change_id, tenant_id, project, environment, application_name, subject_type, subject_name,
            change_type, severity, status, previous_hash, current_hash, previous_payload,
            current_payload, changed_fields, evidence_trace_ids, rationale, detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            change_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            fingerprint["subject_type"],
            fingerprint["subject_name"],
            "material_change",
            severity,
            "open",
            previous_hash,
            current_hash,
            encode_json(previous_payload),
            encode_json(fingerprint["payload"]),
            encode_json(changed_fields),
            encode_json(fingerprint["trace_ids"]),
            rationale,
            fingerprint["observed_at"],
        ),
    )
    upsert_review_task(connection, app_context, change_id, fingerprint, severity, rationale)


def upsert_review_task(
    connection,
    app_context: dict[str, Any],
    change_id: str,
    fingerprint: dict[str, Any],
    severity: str,
    rationale: str,
) -> None:
    task_id = entity_id("review-task", change_id)
    priority = "high" if severity == "High" else "medium"
    title = f"Review {fingerprint['subject_type']} change: {fingerprint['subject_name']}"
    connection.execute(
        """
        INSERT INTO review_tasks (
            task_id, change_id, tenant_id, project, environment, application_name, task_type,
            status, priority, title, rationale, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        ON CONFLICT(task_id) DO UPDATE SET
            status=review_tasks.status,
            priority=excluded.priority,
            title=excluded.title,
            rationale=excluded.rationale,
            updated_at=datetime('now')
        """,
        (
            task_id,
            change_id,
            app_context.get("tenant_id"),
            app_context["project"],
            app_context["environment"],
            app_context["application_name"],
            "material_change_review",
            "open",
            priority,
            title,
            rationale,
        ),
    )


def list_change_events(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    rows = scoped_rows(
        "change_events",
        tenant_id=tenant_id,
        project=project,
        environment=environment,
        order_by="detected_at",
        limit=limit,
        offset=offset,
    )
    return [
        {
            **row,
            "previous_payload": decode_json(row["previous_payload"], {}),
            "current_payload": decode_json(row["current_payload"], {}),
            "changed_fields": decode_json(row["changed_fields"], []),
            "evidence_trace_ids": decode_json(row["evidence_trace_ids"], []),
        }
        for row in rows
    ]


def list_review_tasks(
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    return scoped_rows(
            "review_tasks",
            tenant_id=tenant_id,
            project=project,
            environment=environment,
            order_by="updated_at",
            limit=limit,
            offset=offset,
        )




def count_change_events(
    *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None
) -> int:
    return count_scoped_rows("change_events", tenant_id=tenant_id, project=project, environment=environment)


def count_review_tasks(
    *, tenant_id: str | None = None, project: str | None = None, environment: str | None = None
) -> int:
    return count_scoped_rows("review_tasks", tenant_id=tenant_id, project=project, environment=environment)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Additive portable records, immutable bodies, tenant-serialized mutations."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.storage import db
from app.storage.errors import RecordNotFound
from app.storage.raw_events import connect


def ensure_tables(connection) -> None:
    connection.execute("""CREATE TABLE IF NOT EXISTS portable_records (
        record_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
        project TEXT NOT NULL, environment TEXT NOT NULL, integration_id TEXT NOT NULL,
        external_id TEXT NOT NULL, subject_id TEXT NOT NULL, state TEXT NOT NULL, body TEXT NOT NULL,
        revision_id TEXT NOT NULL, policy_id TEXT NOT NULL, purpose TEXT NOT NULL,
        revision_digest TEXT NOT NULL, check_id TEXT NOT NULL, observed_at TEXT NOT NULL, evidence_result TEXT NOT NULL,
        created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, audited_at TEXT NOT NULL DEFAULT '', decision_id TEXT NOT NULL DEFAULT '',
        UNIQUE (tenant_id, kind, integration_id, project, environment, external_id))""")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_portable_scope ON portable_records(tenant_id, kind, project, environment)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_portable_evidence ON portable_records(tenant_id, kind, subject_id, revision_digest, check_id, observed_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_portable_history ON portable_records(tenant_id, kind, subject_id, revision_id, policy_id, purpose, created_at)"
    )
    connection.execute("""CREATE TABLE IF NOT EXISTS portable_credentials (
        token_hash TEXT PRIMARY KEY, record_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
        purpose TEXT NOT NULL, expires_at TEXT, consumed_at TEXT)""")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def transaction(tenant_id: str):
    with connect() as connection:
        if db.is_postgres():
            key = int.from_bytes(hashlib.sha256(("portable:" + tenant_id).encode()).digest()[:8], "big", signed=True)
            connection.execute("SELECT pg_advisory_xact_lock(?)", (key,))
        else:
            connection.execute("BEGIN IMMEDIATE")
        yield connection


def decode(row) -> dict[str, Any]:
    record = dict(row)
    record["body"] = json.loads(record["body"])
    record["body_digest"] = digest(record["body"])
    return record


def load(connection, tenant_id: str, record_id: str, kind: str | None = None) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM portable_records WHERE tenant_id = ? AND record_id = ?", (tenant_id, record_id)
    ).fetchone()
    if row is None or (kind is not None and row["kind"] != kind):
        raise RecordNotFound("Portable record not found")
    return decode(row)


def records(
    connection,
    tenant_id: str,
    kind: str,
    *,
    project: str | None = None,
    environment: str | None = None,
    integration_id: str | None = None,
    subject_id: str | None = None,
    revision_id: str | None = None,
    policy_id: str | None = None,
    purpose: str | None = None,
    state: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT * FROM portable_records WHERE tenant_id = ? AND kind = ?
        AND (? IS NULL OR project = ?) AND (? IS NULL OR environment = ?)
        AND (? IS NULL OR integration_id = ?) AND (? IS NULL OR subject_id = ?)
        AND (? IS NULL OR revision_id = ?) AND (? IS NULL OR policy_id = ?)
        AND (? IS NULL OR purpose = ?) AND (? IS NULL OR state = ?)
        ORDER BY created_at DESC, record_id LIMIT ? OFFSET ?""",
        (
            tenant_id,
            kind,
            project,
            project,
            environment,
            environment,
            integration_id,
            integration_id,
            subject_id,
            subject_id,
            revision_id,
            revision_id,
            policy_id,
            policy_id,
            purpose,
            purpose,
            state,
            state,
            limit,
            offset,
        ),
    ).fetchall()
    return [decode(row) for row in rows]


def insert(
    connection,
    *,
    tenant_id: str,
    kind: str,
    project: str,
    environment: str,
    integration_id: str,
    external_id: str,
    state: str,
    body: dict[str, Any],
    created_by: str,
) -> dict[str, Any]:
    record_id = str(uuid4())
    connection.execute(
        """INSERT INTO portable_records
        (record_id, tenant_id, kind, project, environment, integration_id, external_id, subject_id, state, body, created_by, created_at, updated_at, revision_id, policy_id, purpose, revision_digest, check_id, observed_at, evidence_result)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record_id,
            tenant_id,
            kind,
            project,
            environment,
            integration_id,
            external_id,
            body.get("system_id", ""),
            state,
            canonical(body),
            created_by,
            datetime.now(UTC).isoformat(),
            datetime.now(UTC).isoformat(),
            body.get("revision_id", ""),
            body.get("policy_id") or "",
            body.get("purpose", ""),
            body.get("revision_digest", ""),
            body.get("check_id", ""),
            datetime.fromisoformat(body["observed_at"].replace("Z", "+00:00"))
            .astimezone(UTC)
            .isoformat(timespec="microseconds")
            if body.get("observed_at")
            else "",
            body.get("result", ""),
        ),
    )
    return load(connection, tenant_id, record_id)


def set_state(connection, record: dict[str, Any], state: str, *, decision_id: str | None = None) -> dict[str, Any]:
    connection.execute(
        "UPDATE portable_records SET state = ?, updated_at = ?, audited_at = '', decision_id = COALESCE(?, decision_id) WHERE tenant_id = ? AND record_id = ?",
        (state, datetime.now(UTC).isoformat(), decision_id, record["tenant_id"], record["record_id"]),
    )
    return load(connection, record["tenant_id"], record["record_id"])

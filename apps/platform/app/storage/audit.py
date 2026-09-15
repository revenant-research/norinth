# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""append-only, tamper-evident audit log

each entry carries a hash chaining it to the previous
(row_hash = SHA-256(prev_hash || canonical(entry))), so any insertion, deletion,
reordering, or field change within the surviving chain breaks it and is caught
by verify_audit_chain(). Tail truncation requires an independent checkpoint
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any

from app.services.observability import histogram_observe

from . import db
from .audit_checkpoint import (
    append_checkpoint,
    checkpoint_lock,
    latest_checkpoint,
    read_checkpoints,
    reconcile_checkpoint,
)
from .entities import encode_json
from .raw_events import connect

_audit_stream = logging.getLogger("norinth.audit")

# chain anchor for the first entry
GENESIS_HASH = "0" * 64


def init_audit() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor_ref TEXT NOT NULL,
                tenant_id TEXT,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                detail TEXT,
                prev_hash TEXT,
                row_hash TEXT,
                row_hmac TEXT,
                hash_version INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        # idempotent migration for pre-existing databases
        for column in ("prev_hash TEXT", "row_hash TEXT", "row_hmac TEXT", "hash_version INTEGER NOT NULL DEFAULT 1"):
            try:
                connection.execute(f"ALTER TABLE audit_logs ADD COLUMN {column}")
            except Exception:
                pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_ref)")


def _audit_keyring() -> dict[str, bytes]:
    """hmac keys available to anchor/verify rows, id -> raw bytes

    keys the chain to a secret outside the db so db-write access alone can't
    recompute a valid chain. a legacy NORINTH_SECRET_KEY is included under the id
    "legacy" so rows written before the keyring still verify; a rotated setup adds
    NORINTH_AUDIT_HMAC_KEYS (a JSON id->secret map) and NORINTH_AUDIT_HMAC_PRIMARY
    """
    ring: dict[str, bytes] = {}
    legacy = os.getenv("NORINTH_SECRET_KEY")
    if legacy:
        ring["legacy"] = legacy.encode("utf-8")
    raw = os.getenv("NORINTH_AUDIT_HMAC_KEYS")
    if raw:
        try:
            entries = json.loads(raw)
        except Exception as error:
            raise RuntimeError("NORINTH_AUDIT_HMAC_KEYS is not valid JSON") from error
        if not isinstance(entries, dict) or not entries:
            raise RuntimeError("NORINTH_AUDIT_HMAC_KEYS must be a non-empty JSON object of {id: secret}")
        for kid, value in entries.items():
            if not isinstance(kid, str) or not kid:
                raise RuntimeError("audit hmac key ids must be non-empty strings")
            ring[kid] = value.encode("utf-8")
    return ring


def _audit_primary_id() -> str | None:
    """id of the key that anchors new rows, or None when no key is configured"""
    ring = _audit_keyring()
    explicit = os.getenv("NORINTH_AUDIT_HMAC_PRIMARY")
    if explicit:
        if explicit not in ring:
            raise RuntimeError(f"NORINTH_AUDIT_HMAC_PRIMARY '{explicit}' is not in the audit hmac keyring")
        return explicit
    if os.getenv("NORINTH_AUDIT_HMAC_KEYS"):
        raise RuntimeError("NORINTH_AUDIT_HMAC_KEYS is set; also set NORINTH_AUDIT_HMAC_PRIMARY to name the active key")
    if "legacy" in ring:
        return "legacy"
    return None


def _hmac(key: bytes, row_hash: str) -> str:
    return hmac.new(key, row_hash.encode("utf-8"), hashlib.sha256).hexdigest()


# each row records the hash algorithm that produced it (hash_version), and
# verification dispatches on it. a future change to the algorithm is a new
# version that leaves existing rows verifiable under the one that wrote them,
# so the chain can evolve without every prior entry reading as tampered
CURRENT_HASH_VERSION = 1


def _hash_v1(
    prev_hash: str,
    created_at: str,
    actor_ref: str,
    tenant_id: str | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    detail_json: str | None,
) -> str:
    # json array canonical form: unambiguous even when a field contains the
    # delimiter
    payload = json.dumps(
        [prev_hash, created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_HASHERS = {1: _hash_v1}


def _compute_row_hash(
    version: int,
    prev_hash: str,
    created_at: str,
    actor_ref: str,
    tenant_id: str | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    detail_json: str | None,
) -> str | None:
    hasher = _HASHERS.get(version)
    if hasher is None:
        return None
    return hasher(prev_hash, created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json)


def _compute_row_hmac(row_hash: str) -> tuple[str | None, str | None]:
    """(hmac, key_id) for a new row under the primary key, or (None, None)"""
    primary = _audit_primary_id()
    if primary is None:
        return None, None
    return _hmac(_audit_keyring()[primary], row_hash), primary


def record_audit(
    *,
    actor_ref: str,
    action: str,
    tenant_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """append a tamper-evident audit entry, chained to the prior one

    the last-hash read and the insert run in one IMMEDIATE transaction so
    concurrent writes can't fork the chain; append-only, no update path
    """
    detail_json = encode_json(detail) if detail is not None else None
    write_started = time.perf_counter()
    with checkpoint_lock():
        connection = connect()
        connection.isolation_level = None  # manage the transaction explicitly
        try:
            connection.execute("BEGIN IMMEDIATE")
            db.serialize_writer(connection)  # single-writer ordering on postgres too
            last = connection.execute("SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = last["row_hash"] if last and last["row_hash"] else GENESIS_HASH
            previous_count = int(connection.execute("SELECT COUNT(*) AS count FROM audit_logs").fetchone()["count"])
            checkpoint = latest_checkpoint(_audit_keyring())
            if checkpoint:
                if checkpoint["count"] > previous_count:
                    raise RuntimeError("Audit database is shorter than the retained checkpoint")
                if checkpoint["count"]:
                    anchored = connection.execute(
                        "SELECT row_hash FROM audit_logs ORDER BY id LIMIT 1 OFFSET ?",
                        (checkpoint["count"] - 1,),
                    ).fetchone()
                    if anchored is None or anchored["row_hash"] != checkpoint["head_hash"]:
                        raise RuntimeError("Audit database contradicts the retained checkpoint")
            created_at = connection.execute("SELECT datetime('now') AS now").fetchone()["now"]
            row_hash = _compute_row_hash(
                CURRENT_HASH_VERSION, prev_hash, created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json
            )
            if row_hash is None:
                raise RuntimeError(f"no audit hasher registered for version {CURRENT_HASH_VERSION}")
            row_hmac, hmac_key_id = _compute_row_hmac(row_hash)
            connection.execute(
                """
                INSERT INTO audit_logs
                    (created_at, actor_ref, tenant_id, action, target_type, target_id, detail, prev_hash, row_hash, row_hmac, hmac_key_id, hash_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json, prev_hash, row_hash, row_hmac, hmac_key_id, CURRENT_HASH_VERSION),
            )
            count = previous_count + 1
            connection.execute("COMMIT")
        finally:
            connection.close()
        if hmac_key_id is not None:
            append_checkpoint(count, row_hash, hmac_key_id, _audit_keyring()[hmac_key_id], _audit_keyring())
    # the audit record also streams to stdout: a siem should see security
    # events (logins, lockouts, resets, exports) without polling the database.
    # the chain in the database stays the tamper-evident record; this is a copy
    histogram_observe(
        "norinth_audit_write_seconds",
        "Audit chain append duration (includes single-writer serialization)",
        time.perf_counter() - write_started,
    )
    _audit_stream.info(
        action,
        extra={
            "actor_ref": actor_ref,
            "tenant_id": tenant_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
        },
    )


def verify_audit_chain(*, tenant_id: str | None = None, check_checkpoint: bool = True) -> dict[str, Any]:
    # Read the database and journal under the same cross-process lock so a
    # concurrent append cannot create a transient false truncation verdict.
    with checkpoint_lock():
        return _verify_audit_chain_unlocked(tenant_id=tenant_id, check_checkpoint=check_checkpoint)


def _verify_audit_chain_unlocked(*, tenant_id: str | None = None, check_checkpoint: bool = True) -> dict[str, Any]:
    """recompute the hash chain and report integrity

    returns {ok, entries, broken_at}; broken_at is the first entry whose hash or
    prev-link doesn't match a recomputation. the chain is global (ordered by id);
    tenant_id is accepted for symmetry but a per-tenant view can't prove nothing
    was removed, so verification always covers the whole chain
    """
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, actor_ref, tenant_id, action, target_type, target_id, detail, prev_hash, row_hash, row_hmac, hmac_key_id, hash_version
            FROM audit_logs ORDER BY id
            """
        ).fetchall()
    ring = _audit_keyring()
    expected_prev = GENESIS_HASH
    for row in rows:
        version = int(row["hash_version"]) if row["hash_version"] is not None else CURRENT_HASH_VERSION
        recomputed = _compute_row_hash(
            version,
            expected_prev,
            row["created_at"],
            row["actor_ref"],
            row["tenant_id"],
            row["action"],
            row["target_type"],
            row["target_id"],
            row["detail"],
        )
        if recomputed is None:
            return {"ok": False, "entries": len(rows), "broken_at": row["id"], "reason": f"unknown hash version {version}"}
        if row["prev_hash"] != expected_prev or row["row_hash"] != recomputed:
            return {"ok": False, "entries": len(rows), "broken_at": row["id"], "reason": "hash chain"}
        # A configured key requires a valid signature on every row. Never
        # repair missing signatures: a database writer can strip them.
        if ring:
            if row["row_hmac"] is None:
                return {"ok": False, "entries": len(rows), "broken_at": row["id"], "reason": "hmac missing"}
            key = ring.get(row["hmac_key_id"] or "legacy")
            if key is None or not hmac.compare_digest(row["row_hmac"], _hmac(key, row["row_hash"])):
                return {"ok": False, "entries": len(rows), "broken_at": row["id"], "reason": "hmac"}
        expected_prev = row["row_hash"]
    if not check_checkpoint:
        return {"ok": True, "entries": len(rows), "broken_at": None, "chain_ok": True}
    checkpoints, checkpoint_error = read_checkpoints(ring)
    if checkpoint_error not in (None, "unavailable", "verification_key_unavailable"):
        return {"ok": False, "entries": len(rows), "broken_at": None, "reason": checkpoint_error,
                "chain_ok": True, "completeness_ok": False, "checkpoint_status": "invalid"}
    if not checkpoints:
        return {"ok": True, "entries": len(rows), "broken_at": None, "chain_ok": True,
                "completeness_ok": None, "checkpoint_status": checkpoint_error or "unavailable",
                "unanchored_entries": len(rows)}
    latest = checkpoints[-1]
    if len(rows) < latest["count"] or (len(rows) == latest["count"] and expected_prev != latest["head_hash"]):
        return {"ok": False, "entries": len(rows), "broken_at": None, "reason": "checkpoint mismatch",
                "chain_ok": True, "completeness_ok": False, "checkpoint_status": "mismatch",
                "checkpoint": latest}
    # A newer database may contain an interval not yet independently anchored,
    # such as after an outage or a commit preceding a checkpoint write.
    unanchored = len(rows) - latest["count"]
    if unanchored and rows[latest["count"] - 1]["row_hash"] != latest["head_hash"]:
        return {"ok": False, "entries": len(rows), "broken_at": None, "reason": "checkpoint mismatch",
                "chain_ok": True, "completeness_ok": False, "checkpoint_status": "mismatch",
                "checkpoint": latest}
    from datetime import UTC, datetime, timedelta

    age = datetime.now(UTC) - datetime.fromisoformat(latest["created_at"])
    fresh = age <= timedelta(hours=24)
    prior_unanchored = latest["anchored_from"] - 1
    reconciled = any(entry.get("kind") == "reconcile" for entry in checkpoints)
    current = fresh and unanchored == 0 and prior_unanchored == 0 and not reconciled
    return {"ok": True, "entries": len(rows), "broken_at": None, "chain_ok": True,
            "completeness_ok": current,
            "checkpoint_status": "partial_history" if prior_unanchored or reconciled else "current" if current else "stale",
            "checkpoint": latest, "unanchored_entries": unanchored,
            "unanchored_before_checkpoint": prior_unanchored}


def validate_audit_at_startup() -> None:
    """Verify without repairing history, before any background workers start."""
    _audit_primary_id()  # validate write-key configuration even on an empty log
    result = verify_audit_chain()
    if not result["ok"]:
        raise RuntimeError(
            f"Audit integrity check failed at entry {result['broken_at']}: {result['reason']}. "
            "Audit history was not repaired. Investigate tampering or missing verification keys."
        )


def reconcile_audit_after_restore(*, reason: str, expected_seal: str) -> dict[str, Any]:
    """Operator-only restore reconciliation; never called by startup or API."""
    with checkpoint_lock():
        chain = _verify_audit_chain_unlocked(check_checkpoint=False)
        if not chain["ok"]:
            raise RuntimeError(f"Restored audit chain is invalid: {chain['reason']}")
        primary = _audit_primary_id()
        if primary is None:
            raise RuntimeError("Audit HMAC key is required for checkpoint reconciliation")
        with connect() as connection:
            head = connection.execute("SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        reconcile_checkpoint(chain["entries"], head["row_hash"] if head else GENESIS_HASH,
                             reason, expected_seal, primary, _audit_keyring()[primary], _audit_keyring())
        return _verify_audit_chain_unlocked()


def _audit_filters(tenant_id: str | None, actor_ref: str | None, action: str | None) -> tuple[str, dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if tenant_id:
        clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if actor_ref:
        clauses.append("actor_ref = :actor_ref")
        params["actor_ref"] = actor_ref
    if action:
        clauses.append("action = :action")
        params["action"] = action
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def count_audit_logs(
    *, tenant_id: str | None = None, actor_ref: str | None = None, action: str | None = None
) -> int:
    where, params = _audit_filters(tenant_id, actor_ref, action)
    with connect() as connection:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM audit_logs {where}", params).fetchone()
    return int(row["count"])


def list_audit_logs(
    *,
    tenant_id: str | None = None,
    actor_ref: str | None = None,
    action: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """newest-first window of audit entries"""
    where, params = _audit_filters(tenant_id, actor_ref, action)
    params.update({"limit": limit, "offset": offset})
    query = f"SELECT * FROM audit_logs {where} ORDER BY id DESC LIMIT :limit OFFSET :offset"
    with connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]

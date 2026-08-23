"""append-only, tamper-evident audit log.

each entry carries a hash chaining it to the previous
(row_hash = SHA-256(prev_hash || canonical(entry))), so any insertion, deletion,
reordering, or field change breaks the chain and is caught by
verify_audit_chain().
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from . import db
from .entities import encode_json
from .raw_events import connect

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
                row_hmac TEXT
            )
            """
        )
        # idempotent migration for pre-existing databases
        for column in ("prev_hash TEXT", "row_hash TEXT", "row_hmac TEXT"):
            try:
                connection.execute(f"ALTER TABLE audit_logs ADD COLUMN {column}")
            except Exception:
                pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_ref)")


def _audit_hmac_key() -> bytes | None:
    """key the chain to a secret outside the db (NORINTH_SECRET_KEY) so db write
    access alone can't recompute a valid chain; absent in dev, hash-only there"""
    key = os.getenv("NORINTH_SECRET_KEY")
    return key.encode("utf-8") if key else None


def _compute_row_hash(
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


def _compute_row_hmac(row_hash: str) -> str | None:
    key = _audit_hmac_key()
    if key is None:
        return None
    return hmac.new(key, row_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def record_audit(
    *,
    actor_ref: str,
    action: str,
    tenant_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """append a tamper-evident audit entry, chained to the prior one.

    the last-hash read and the insert run in one IMMEDIATE transaction so
    concurrent writes can't fork the chain; append-only, no update path.
    """
    detail_json = encode_json(detail) if detail is not None else None
    connection = connect()
    connection.isolation_level = None  # manage the transaction explicitly
    try:
        connection.execute("BEGIN IMMEDIATE")
        db.serialize_writer(connection)  # single-writer ordering on postgres too
        last = connection.execute("SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["row_hash"] if last and last["row_hash"] else GENESIS_HASH
        created_at = connection.execute("SELECT datetime('now') AS now").fetchone()["now"]
        row_hash = _compute_row_hash(
            prev_hash, created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json
        )
        row_hmac = _compute_row_hmac(row_hash)
        connection.execute(
            """
            INSERT INTO audit_logs
                (created_at, actor_ref, tenant_id, action, target_type, target_id, detail, prev_hash, row_hash, row_hmac)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json, prev_hash, row_hash, row_hmac),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()


def verify_audit_chain(*, tenant_id: str | None = None) -> dict[str, Any]:
    """recompute the hash chain and report integrity.

    returns {ok, entries, broken_at}; broken_at is the first entry whose hash or
    prev-link doesn't match a recomputation. the chain is global (ordered by id);
    tenant_id is accepted for symmetry but a per-tenant view can't prove nothing
    was removed, so verification always covers the whole chain.
    """
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, actor_ref, tenant_id, action, target_type, target_id, detail, prev_hash, row_hash, row_hmac
            FROM audit_logs ORDER BY id
            """
        ).fetchall()
    key = _audit_hmac_key()
    expected_prev = GENESIS_HASH
    for row in rows:
        recomputed = _compute_row_hash(
            expected_prev,
            row["created_at"],
            row["actor_ref"],
            row["tenant_id"],
            row["action"],
            row["target_type"],
            row["target_id"],
            row["detail"],
        )
        if row["prev_hash"] != expected_prev or row["row_hash"] != recomputed:
            return {"ok": False, "entries": len(rows), "broken_at": row["id"], "reason": "hash chain"}
        # a row written with an hmac must verify under the current key; without
        # the key the chain can't be reproduced
        if row["row_hmac"] is not None:
            if key is None or not hmac.compare_digest(row["row_hmac"], _compute_row_hmac(row["row_hash"]) or ""):
                return {"ok": False, "entries": len(rows), "broken_at": row["id"], "reason": "hmac"}
        expected_prev = row["row_hash"]
    return {"ok": True, "entries": len(rows), "broken_at": None}


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

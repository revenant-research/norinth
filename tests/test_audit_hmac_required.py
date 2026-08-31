# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""an install holding a key requires an hmac on every audit row

verification checked the hmac only when the row carried one, and that column
lives in the table a database-writing attacker is already editing. nulling it
across the table and recomputing the unkeyed sha-256 chain from genesis passed
verification, which is the one adversary the anchor exists for
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

KEY = "c2VjcmV0LWtleS0zMi1ieXRlcy1mb3ItYXVkaXQtdGVzdA=="


def _write(actor: str = "ceo@corp", target: str = "g1") -> None:
    from app.storage.audit import record_audit

    record_audit(actor_ref=actor, tenant_id="t1", action="gate.approve",
                 target_type="gate", target_id=target, detail={"n": target})


def _execute(sql: str, params: dict | None = None) -> None:
    """run a statement through the platform's own connection, so this exercises
    whichever backend the suite is pointed at"""
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute(sql, params or {})


def _rows() -> list[dict]:
    from app.storage.raw_events import connect

    with connect() as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()]


def _rewrite_chain() -> None:
    """recompute a self-consistent unkeyed chain over whatever the rows now say"""
    from app.storage.audit import CURRENT_HASH_VERSION, GENESIS_HASH, _compute_row_hash

    prev = GENESIS_HASH
    for row in _rows():
        row_hash = _compute_row_hash(
            CURRENT_HASH_VERSION, prev, row["created_at"], row["actor_ref"], row["tenant_id"],
            row["action"], row["target_type"], row["target_id"], row["detail"],
        )
        _execute(
            "UPDATE audit_logs SET prev_hash = :prev, row_hash = :hash WHERE id = :id",
            {"prev": prev, "hash": row_hash, "id": row["id"]},
        )
        prev = row_hash


@pytest.fixture()
def anchored_chain(fresh_db, monkeypatch):
    """three rows on top of whatever bootstrap wrote, all anchored under a key"""
    monkeypatch.setenv("NORINTH_SECRET_KEY", KEY)
    from app.storage.audit import ensure_audit_hmac_backfill

    for target in ("g1", "f1", "p1"):
        _write(target=target)
    ensure_audit_hmac_backfill()
    return _rows()


def test_baseline_chain_verifies(anchored_chain):
    from app.storage.audit import verify_audit_chain

    assert all(row["row_hmac"] for row in anchored_chain)
    assert verify_audit_chain()["ok"] is True


def test_stripping_the_hmac_and_rewriting_the_chain_is_caught(anchored_chain):
    from app.storage.audit import verify_audit_chain

    first = anchored_chain[0]["id"]
    _execute("UPDATE audit_logs SET actor_ref = 'intern@corp' WHERE id = :id", {"id": first})
    _execute("UPDATE audit_logs SET row_hmac = NULL, hmac_key_id = NULL")
    _rewrite_chain()

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] == first
    assert result["reason"] == "hmac missing"


def test_forged_hmac_without_the_key_is_caught(anchored_chain):
    from app.storage.audit import verify_audit_chain

    first = anchored_chain[0]["id"]
    _execute("UPDATE audit_logs SET actor_ref = 'intern@corp' WHERE id = :id", {"id": first})
    _execute("UPDATE audit_logs SET row_hmac = 'deadbeef', hmac_key_id = 'legacy'")
    _rewrite_chain()

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["reason"] == "hmac"


def test_single_row_tamper_still_breaks_the_hash_chain(anchored_chain):
    from app.storage.audit import verify_audit_chain

    target = anchored_chain[-1]["id"]
    _execute("UPDATE audit_logs SET actor_ref = 'intern@corp' WHERE id = :id", {"id": target})

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] == target
    assert result["reason"] == "hash chain"


def test_install_with_no_key_still_verifies_its_hash_chain(fresh_db, monkeypatch):
    """nothing to anchor with, so the unkeyed chain is all there is to check"""
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("NORINTH_AUDIT_HMAC_KEYS", raising=False)
    from app.storage.audit import ensure_audit_hmac_backfill, verify_audit_chain

    _write()
    assert ensure_audit_hmac_backfill() == 0
    assert verify_audit_chain()["ok"] is True


def test_rows_written_before_a_key_are_anchored_on_the_next_boot(fresh_db, monkeypatch):
    """the upgrade path: rows written unkeyed, then the operator sets a key"""
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("NORINTH_AUDIT_HMAC_KEYS", raising=False)
    from app.storage.audit import ensure_audit_hmac_backfill, verify_audit_chain

    for target in ("a", "b"):
        _write(target=target)
    unanchored = sum(1 for row in _rows() if row["row_hmac"] is None)
    assert unanchored >= 2

    monkeypatch.setenv("NORINTH_SECRET_KEY", KEY)
    assert ensure_audit_hmac_backfill() == unanchored
    assert verify_audit_chain()["ok"] is True
    # it does not re-anchor rows that already carry one
    assert ensure_audit_hmac_backfill() == 0

    _write(target="c")
    assert verify_audit_chain()["ok"] is True

    # the strip attack now fails on the upgraded install
    first = _rows()[0]["id"]
    _execute("UPDATE audit_logs SET row_hmac = NULL WHERE id = :id", {"id": first})
    assert verify_audit_chain()["reason"] == "hmac missing"

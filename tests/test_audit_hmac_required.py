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

KEY = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE='


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

    for target in ("g1", "f1", "p1"):
        _write(target=target)
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
    from app.storage.audit import validate_audit_at_startup, verify_audit_chain

    _write()
    validate_audit_at_startup()
    assert verify_audit_chain()["ok"] is True


def test_unsigned_history_is_not_signed_when_a_key_is_added(fresh_db, monkeypatch):
    from app.storage.audit import validate_audit_at_startup, verify_audit_chain

    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("NORINTH_AUDIT_HMAC_KEYS", raising=False)
    for target in ("a", "b"):
        _write(target=target)
    snapshot = _rows()
    monkeypatch.setenv("NORINTH_SECRET_KEY", KEY)
    with pytest.raises(RuntimeError, match="hmac missing"):
        validate_audit_at_startup()
    assert _rows() == snapshot
    assert verify_audit_chain()["reason"] == "hmac missing"


def _run_module(module: str, *args: str):
    import os
    import subprocess

    env = {**os.environ, "PYTHONPATH": str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform")}
    return subprocess.run([sys.executable, "-m", module, *args], env=env, capture_output=True, text=True, timeout=30)


def test_forged_history_stays_rejected_across_real_startup(anchored_chain):
    from app.storage.audit import verify_audit_chain

    _execute("UPDATE audit_logs SET actor_ref = 'intern@corp', row_hmac = NULL, hmac_key_id = NULL")
    _rewrite_chain()
    tampered = _rows()
    # A fresh interpreter executes main's actual migration/startup sequence.
    for _ in range(2):
        result = _run_module("app.main")
        assert result.returncode != 0
        assert "Audit integrity check failed" in result.stderr, result.stderr
        assert "hmac missing" in result.stderr
        assert _rows() == tampered
        assert verify_audit_chain()["reason"] == "hmac missing"


def test_fresh_and_rotated_key_startup_are_read_only(fresh_db, monkeypatch):
    import json

    from app.storage.audit import validate_audit_at_startup

    validate_audit_at_startup()  # empty database is legitimate
    _write(target="old")
    monkeypatch.setenv("NORINTH_AUDIT_HMAC_KEYS", json.dumps({"new": "new-audit-key"}))
    monkeypatch.setenv("NORINTH_AUDIT_HMAC_PRIMARY", "new")
    _write(target="new")
    before = _rows()
    validate_audit_at_startup()
    assert _rows() == before
    result = _run_module("app.main")
    assert result.returncode == 0, result.stderr
    assert _rows() == before
    monkeypatch.delenv("NORINTH_SECRET_KEY")
    with pytest.raises(RuntimeError, match="hmac"):
        validate_audit_at_startup()
    assert _rows() == before

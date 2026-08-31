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
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

KEY = "c2VjcmV0LWtleS0zMi1ieXRlcy1mb3ItYXVkaXQtdGVzdA=="


@pytest.fixture()
def audit_db(tmp_path, monkeypatch):
    """a fresh chain of three rows, anchored under a configured key"""
    path = tmp_path / "audit.sqlite3"
    monkeypatch.setenv("NORINTH_PLATFORM_DB", str(path))
    monkeypatch.setenv("NORINTH_SECRET_KEY", KEY)
    from app.storage import migrations

    migrations.run_migrations()
    from app.storage.audit import ensure_audit_hmac_backfill, record_audit

    for target in ("g1", "f1", "p1"):
        record_audit(actor_ref="ceo@corp", tenant_id="t1", action="gate.approve",
                     target_type="gate", target_id=target, detail={"n": target})
    ensure_audit_hmac_backfill()
    return path


def _connect(path):
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    return connection


def _rewrite_chain(path):
    """recompute a self-consistent unkeyed chain over whatever the rows now say"""
    from app.storage.audit import CURRENT_HASH_VERSION, GENESIS_HASH, _compute_row_hash

    connection = _connect(path)
    prev = GENESIS_HASH
    for row in connection.execute("SELECT * FROM audit_logs ORDER BY id").fetchall():
        row_hash = _compute_row_hash(
            CURRENT_HASH_VERSION, prev, row["created_at"], row["actor_ref"], row["tenant_id"],
            row["action"], row["target_type"], row["target_id"], row["detail"],
        )
        connection.execute("UPDATE audit_logs SET prev_hash=?, row_hash=? WHERE id=?", (prev, row_hash, row["id"]))
        prev = row_hash
    connection.commit()
    connection.close()


def test_baseline_chain_verifies(audit_db):
    from app.storage.audit import verify_audit_chain

    assert verify_audit_chain() == {"ok": True, "entries": 3, "broken_at": None}


def test_stripping_the_hmac_and_rewriting_the_chain_is_caught(audit_db):
    from app.storage.audit import verify_audit_chain

    connection = _connect(audit_db)
    connection.execute("UPDATE audit_logs SET actor_ref='intern@corp' WHERE id=1")
    connection.execute("UPDATE audit_logs SET row_hmac=NULL, hmac_key_id=NULL")
    connection.commit()
    connection.close()
    _rewrite_chain(audit_db)

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] == 1
    assert result["reason"] == "hmac missing"


def test_forged_hmac_without_the_key_is_caught(audit_db):
    from app.storage.audit import verify_audit_chain

    connection = _connect(audit_db)
    connection.execute("UPDATE audit_logs SET actor_ref='intern@corp' WHERE id=1")
    connection.execute("UPDATE audit_logs SET row_hmac='deadbeef', hmac_key_id='legacy'")
    connection.commit()
    connection.close()
    _rewrite_chain(audit_db)

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["reason"] == "hmac"


def test_single_row_tamper_still_breaks_the_hash_chain(audit_db):
    from app.storage.audit import verify_audit_chain

    connection = _connect(audit_db)
    connection.execute("UPDATE audit_logs SET actor_ref='intern@corp' WHERE id=2")
    connection.commit()
    connection.close()

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] == 2
    assert result["reason"] == "hash chain"


def test_install_with_no_key_still_verifies_its_hash_chain(tmp_path, monkeypatch):
    """nothing to anchor with, so the unkeyed chain is all there is to check"""
    monkeypatch.setenv("NORINTH_PLATFORM_DB", str(tmp_path / "nokey.sqlite3"))
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("NORINTH_AUDIT_HMAC_KEYS", raising=False)
    from app.storage import migrations

    migrations.run_migrations()
    from app.storage.audit import ensure_audit_hmac_backfill, record_audit, verify_audit_chain

    record_audit(actor_ref="ceo@corp", tenant_id="t1", action="x", target_type="y", target_id="a")
    assert ensure_audit_hmac_backfill() == 0
    assert verify_audit_chain()["ok"] is True


def test_rows_written_before_a_key_are_anchored_on_the_next_boot(tmp_path, monkeypatch):
    """the upgrade path: two rows written unkeyed, then the operator sets a key"""
    monkeypatch.setenv("NORINTH_PLATFORM_DB", str(tmp_path / "upgrade.sqlite3"))
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    from app.storage import migrations

    migrations.run_migrations()
    from app.storage.audit import ensure_audit_hmac_backfill, record_audit, verify_audit_chain

    for target in ("a", "b"):
        record_audit(actor_ref="ceo@corp", tenant_id="t1", action="x", target_type="y", target_id=target)

    monkeypatch.setenv("NORINTH_SECRET_KEY", KEY)
    assert ensure_audit_hmac_backfill() == 2
    assert verify_audit_chain()["ok"] is True
    # and it does not re-anchor rows that already carry one
    assert ensure_audit_hmac_backfill() == 0

    record_audit(actor_ref="ceo@corp", tenant_id="t1", action="x", target_type="y", target_id="c")
    assert verify_audit_chain()["ok"] is True

    # the strip attack now fails on the upgraded install
    connection = _connect(tmp_path / "upgrade.sqlite3")
    connection.execute("UPDATE audit_logs SET row_hmac=NULL WHERE id=1")
    connection.commit()
    connection.close()
    assert verify_audit_chain()["reason"] == "hmac missing"

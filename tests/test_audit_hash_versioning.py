"""the audit chain records the hash algorithm per row so it can evolve

changing the hash algorithm without this made every prior row read as tampered,
because verification recomputed old rows with the new algorithm. rows now record
the version that wrote them and verification dispatches on it
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _write_some_entries(n: int = 3) -> None:
    from app.storage.audit import record_audit

    for i in range(n):
        record_audit(actor_ref=f"u{i}", action="test.action", tenant_id="acme",
                     target_type="thing", target_id=str(i), detail={"i": i})


def test_a_fresh_chain_verifies_and_stamps_the_current_version(fresh_db):
    from app.storage.audit import CURRENT_HASH_VERSION, verify_audit_chain
    from app.storage.raw_events import connect

    _write_some_entries()
    result = verify_audit_chain()
    assert result["ok"] is True, result
    assert result["broken_at"] is None

    with connect() as connection:
        versions = [r["hash_version"] for r in connection.execute("SELECT hash_version FROM audit_logs").fetchall()]
    assert versions and all(v == CURRENT_HASH_VERSION for v in versions), versions


def test_a_future_algorithm_leaves_todays_rows_verifiable(fresh_db):
    """simulate the next algorithm change: register a v2 hasher, write a row with
    it, and confirm the version-1 rows written before it still verify"""
    from app.storage import audit
    from app.storage.audit import record_audit, verify_audit_chain

    _write_some_entries(2)  # version 1 rows

    def _hash_v2(prev_hash, created_at, actor_ref, tenant_id, action, target_type, target_id, detail_json):
        import hashlib
        return "v2:" + hashlib.sha256(f"{prev_hash}{created_at}{action}".encode()).hexdigest()

    audit._HASHERS[2] = _hash_v2
    original = audit.CURRENT_HASH_VERSION
    audit.CURRENT_HASH_VERSION = 2
    try:
        record_audit(actor_ref="u-new", action="post.upgrade", tenant_id="acme", target_id="x")
        # the mixed chain — v1 rows then a v2 row — verifies end to end
        assert verify_audit_chain()["ok"] is True
    finally:
        audit.CURRENT_HASH_VERSION = original
        del audit._HASHERS[2]


def test_an_unknown_version_fails_loudly_rather_than_silently(fresh_db):
    from app.storage.audit import verify_audit_chain
    from app.storage.raw_events import connect

    _write_some_entries(1)
    # a row claiming an algorithm this build does not have
    with connect() as connection:
        connection.execute("UPDATE audit_logs SET hash_version = 99 WHERE id = 1")

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] == 1
    assert "unknown hash version" in result["reason"], result


def test_record_audit_fails_loudly_if_the_current_hasher_is_missing(fresh_db, monkeypatch):
    """a null row hash would break the chain silently; writing must refuse it"""
    import pytest
    from app.storage import audit

    # point the current version at one with no registered hasher
    monkeypatch.setattr(audit, "CURRENT_HASH_VERSION", 999)
    with pytest.raises(RuntimeError, match="no audit hasher"):
        audit.record_audit(actor_ref="u", action="a", tenant_id="acme", target_id="x")

    # nothing was written: the chain is unbroken
    assert audit.verify_audit_chain()["ok"] is True

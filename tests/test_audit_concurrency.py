"""The audit chain does not fork under concurrent writes (critical C4), on
either backend, and the HMAC anchor detects a chain rewritten without the key.
"""

from __future__ import annotations

import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_concurrent_audit_writes_do_not_fork(fresh_db):
    from app.storage.audit import record_audit, verify_audit_chain

    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for i in range(25):
                record_audit(actor_ref=f"w{n}", action="test", tenant_id="acme", target_type="t", target_id=f"{n}-{i}")
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, errors
    result = verify_audit_chain()
    assert result["ok"] is True, result
    assert result["entries"] >= 200

    # No two rows share a prev_hash (a fork would).
    from app.storage.raw_events import connect

    with connect() as connection:
        prevs = [r["prev_hash"] for r in connection.execute("SELECT prev_hash FROM audit_logs WHERE prev_hash IS NOT NULL").fetchall()]
    assert len(prevs) == len(set(prevs)), "duplicate prev_hash means the chain forked"


def test_hmac_anchor_detects_rewrite_without_the_key(fresh_db, monkeypatch):
    monkeypatch.setenv("NORINTH_SECRET_KEY", "a-server-side-secret-not-in-the-db")
    from app.storage.audit import record_audit, verify_audit_chain
    from app.storage.raw_events import connect

    for i in range(5):
        record_audit(actor_ref="admin", action="auth.login", tenant_id="acme", target_type="user", target_id=f"u{i}")
    assert verify_audit_chain()["ok"] is True

    # A DBA rewrites a row and recomputes the plain hash chain from that point,
    # but cannot recompute the HMAC without the key.
    import hashlib
    import json

    from app.storage.audit import GENESIS_HASH

    with connect() as connection:
        rows = [dict(r) for r in connection.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()]
        # tamper the 3rd row's action, then rebuild hashes (not hmacs) forward
        expected_prev = GENESIS_HASH
        for idx, row in enumerate(rows):
            action = "PRIVILEGE-GRANTED" if idx == 2 else row["action"]
            payload = json.dumps([expected_prev, row["created_at"], row["actor_ref"], row["tenant_id"], action, row["target_type"], row["target_id"], row["detail"]], separators=(",", ":"), ensure_ascii=True)
            new_hash = hashlib.sha256(payload.encode()).hexdigest()
            connection.execute("UPDATE audit_logs SET action = ?, prev_hash = ?, row_hash = ? WHERE id = ?", (action, expected_prev, new_hash, row["id"]))
            expected_prev = new_hash

    result = verify_audit_chain()
    assert result["ok"] is False and result["reason"] == "hmac", result

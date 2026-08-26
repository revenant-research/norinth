"""tamper-evident audit logging"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _generate_some_audit_events(super_admin_client):
    # provisioning an org records several audit entries (login, change_password,
    # org.provision, role.assign, ...)
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "a@acme.test",
            "admin_display_name": "A",
            "admin_password": "acme-admin-pw-1",
        },
    )


def test_audit_chain_verifies_ok(super_admin_client):
    _generate_some_audit_events(super_admin_client)
    resp = super_admin_client.get("/api/admin/audit-logs/verify")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["entries"] >= 2
    assert body["broken_at"] is None


def test_modifying_a_row_breaks_the_chain(super_admin_client):
    _generate_some_audit_events(super_admin_client)
    from app.storage.audit import verify_audit_chain
    from app.storage.raw_events import connect

    with connect() as connection:
        row = connection.execute("SELECT id FROM audit_logs ORDER BY id LIMIT 1").fetchone()
        target_id = row["id"]
        # change an entry's action without updating hashes
        connection.execute(
            "UPDATE audit_logs SET action = 'tampered' WHERE id = ?", (target_id,)
        )

    result = verify_audit_chain()
    assert result["ok"] is False
    assert result["broken_at"] == target_id


def test_deleting_a_row_breaks_the_chain(super_admin_client):
    _generate_some_audit_events(super_admin_client)
    from app.storage.audit import verify_audit_chain
    from app.storage.raw_events import connect

    with connect() as connection:
        rows = connection.execute("SELECT id FROM audit_logs ORDER BY id").fetchall()
        assert len(rows) >= 3
        middle_id = rows[len(rows) // 2]["id"]
        connection.execute("DELETE FROM audit_logs WHERE id = ?", (middle_id,))

    result = verify_audit_chain()
    # entry after the deleted one links to a missing prev_hash so chain breaks there
    assert result["ok"] is False
    assert result["broken_at"] is not None


def test_audit_hmac_key_rotation(client, monkeypatch):
    """rotating the audit hmac key keeps old rows verifiable and anchors new rows
    to the new key; dropping the old key from the ring breaks its rows"""
    import base64
    import json
    import os

    from app.storage.audit import record_audit, verify_audit_chain
    from app.storage.raw_events import connect

    # conftest set NORINTH_SECRET_KEY (the legacy hmac key); write a row under it
    record_audit(actor_ref="a", action="first.event", tenant_id="acme")

    # rotate: a new primary key, legacy kept in the ring for the old rows
    new_key = base64.urlsafe_b64encode(os.urandom(24)).decode()
    monkeypatch.setenv("NORINTH_AUDIT_HMAC_KEYS", json.dumps({"2026a": new_key}))
    monkeypatch.setenv("NORINTH_AUDIT_HMAC_PRIMARY", "2026a")
    record_audit(actor_ref="a", action="second.event", tenant_id="acme")

    # both rows verify — each under the key that anchored it
    assert verify_audit_chain()["ok"] is True

    with connect() as connection:
        kids = [r["hmac_key_id"] for r in connection.execute(
            "SELECT hmac_key_id FROM audit_logs WHERE action IN ('first.event', 'second.event') ORDER BY id"
        ).fetchall()]
    assert kids == ["legacy", "2026a"]

    # drop the legacy key from the ring: its rows can no longer be verified, which
    # proves verification uses each row's own key rather than one global key
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    broken = verify_audit_chain()
    assert broken["ok"] is False
    assert broken["reason"] == "hmac"


def test_verify_endpoint_requires_super_admin(super_admin_client):
    # non-super org admin cannot verify the chain
    _generate_some_audit_events(super_admin_client)
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

    with TestClient(app) as org:
        login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
        resp = org.get("/api/admin/audit-logs/verify")
        assert resp.status_code == 403

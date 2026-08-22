"""Regression tests for tamper-evident audit logging (audit H-9)."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _generate_some_audit_events(super_admin_client):
    # Provisioning an org records several audit entries (login, change_password,
    # org.provision, role.assign, ...).
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
        # Tamper: change the action of an existing entry without updating hashes.
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
    # The entry after the deleted one now has a prev_hash that links to a missing
    # row, so the chain breaks there.
    assert result["ok"] is False
    assert result["broken_at"] is not None


def test_verify_endpoint_requires_super_admin(super_admin_client):
    # Provision an org and confirm its (non-super) admin cannot verify the chain.
    _generate_some_audit_events(super_admin_client)
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

    with TestClient(app) as org:
        login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
        resp = org.get("/api/admin/audit-logs/verify")
        assert resp.status_code == 403

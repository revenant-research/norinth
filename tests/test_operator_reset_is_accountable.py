"""a platform operator's password reset is visible and terminal, not silent

the super admin is otherwise walled out of tenant data. resetting one of an
organization's users is a legitimate ops action, but it must be accountable:
the affected organization is notified and the target's live sessions are dropped
so the reset can't be a quiet way to ride an existing login.
"""

from __future__ import annotations

from tests.helpers import login_and_activate


def test_operator_reset_notifies_the_org_and_kills_sessions(super_admin_client):
    from app.main import app
    from app.storage.audit import list_audit_logs
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={
        "tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
        "admin_display_name": "OA", "admin_password": "oa-password-1"})

    # the org admin has a live, authenticated session
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    assert org.get("/api/auth/me").status_code == 200

    # a platform operator resets that account
    resp = super_admin_client.post("/api/admin/users/oa@acme.test/reset-password")
    assert resp.status_code == 200, resp.text
    assert resp.json()["temporary_password"]

    # the target's existing session is now dead
    assert org.get("/api/auth/me").status_code == 401

    # the organization is notified of the operator action (outbox row queued)...
    with connect() as connection:
        notified = connection.execute(
            "SELECT COUNT(*) AS n FROM notification_outbox WHERE tenant_id = ? AND event_type = ?",
            ("acme", "account.reset_by_operator"),
        ).fetchone()["n"]
    assert notified >= 1

    # ...and the reset is recorded in the tenant's audit trail
    actions = [r["action"] for r in list_audit_logs(tenant_id="acme")]
    assert "account.reset_password" in actions
    org.close()

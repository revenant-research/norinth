"""an organization administrator's password reset is visible and terminal

administrators cannot hold decision roles, so resetting a decision holder's
password and MFA was the one way an administrator could come to act with
that authority, and the org-plane reset neither ended the target's sessions
nor told anyone. it now ends the sessions, notifies the target, and when the
target holds a decision role tells the other administrators as it happens
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import login_and_activate


def _org(super_admin_client):
    from app.main import app

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    org = TestClient(app)
    org.__enter__()
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    return org


def _outbox(event_type: str) -> list[dict]:
    from app.storage.raw_events import connect

    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM notification_outbox WHERE tenant_id = 'acme' AND event_type = ?", (event_type,)
        ).fetchall()
    return [dict(row) for row in rows]


def test_reset_of_a_decision_holder_ends_sessions_and_alerts_the_other_admins(super_admin_client):
    from app.main import app
    from app.storage.audit import list_audit_logs

    org = _org(super_admin_client)
    assert (
        org.post(
            "/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev", "password": "rev-pw-123456"}
        ).status_code
        == 200
    )
    assert (
        org.post(
            "/api/org/role-assignments", json={"user_ref": "rev@acme.test", "role": "governance_reviewer"}
        ).status_code
        == 200
    )

    reviewer = TestClient(app)
    login_and_activate(reviewer, "rev@acme.test", "rev-pw-123456")
    assert reviewer.get("/api/auth/me").status_code == 200

    reset = org.post("/api/org/users/rev@acme.test/reset-password")
    assert reset.status_code == 200, reset.text
    assert reset.json()["temporary_password"]

    # the reviewer's live session is gone
    assert reviewer.get("/api/auth/me").status_code == 401

    # the reviewer is told, and so are the administrators
    assert len(_outbox("account.reset_by_admin")) == 1
    alerts = _outbox("account.decision_holder_reset")
    assert len(alerts) >= 1
    assert "governance_reviewer" in alerts[0]["subject"]

    import json

    (entry,) = [row for row in list_audit_logs(tenant_id="acme", action="user.reset_password")]
    assert json.loads(entry["detail"])["decision_roles"] == ["governance_reviewer"]
    reviewer.close()
    org.close()


def test_reset_of_a_plain_user_tells_the_user_only(super_admin_client):
    org = _org(super_admin_client)
    assert (
        org.post(
            "/api/org/users", json={"email": "viewer@acme.test", "display_name": "V", "password": "viewer-pw-123456"}
        ).status_code
        == 200
    )
    assert org.post("/api/org/users/viewer@acme.test/reset-password").status_code == 200
    assert len(_outbox("account.reset_by_admin")) == 1
    assert _outbox("account.decision_holder_reset") == []
    org.close()

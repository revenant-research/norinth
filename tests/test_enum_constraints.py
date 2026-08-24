"""constrained decision/status enums reject free-form values"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org(super_admin_client, tid="acme", email="oa@acme.test"):
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tid,
            "name": tid,
            "admin_email": email,
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    from app.main import app
    from fastapi.testclient import TestClient

    org = TestClient(app)
    login_and_activate(org, email, "oa-password-1")
    return org


def test_decision_rejects_unknown_verb(super_admin_client):
    org = _org(super_admin_client)
    org.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "G", "password": "gov-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        resp = gov.post(
            "/api/decisions",
            json={
                "target_type": "review_task",
                "target_id": "whatever",
                "decision": "totally_done",  # not a real workflow verb
                "rationale": "Reviewed the evidence and this looks acceptable.",
            },
        )
        assert resp.status_code == 400
        assert "decision must be one of" in resp.json()["detail"]
    org.close()


def test_org_user_status_is_constrained(super_admin_client):
    org = _org(super_admin_client)
    resp = org.post(
        "/api/org/users",
        json={"email": "u@acme.test", "display_name": "U", "password": "u-password-1", "status": "wizard"},
    )
    assert resp.status_code == 400
    org.close()


def test_role_assignment_status_is_constrained(super_admin_client):
    org = _org(super_admin_client)
    org.post("/api/org/users", json={"email": "r@acme.test", "display_name": "R", "password": "r-password-1"})
    resp = org.post(
        "/api/org/role-assignments",
        json={"user_ref": "r@acme.test", "role": "risk_owner", "status": "sideways"},
    )
    assert resp.status_code == 400
    org.close()

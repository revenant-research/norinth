"""separation of duties: org_admin can't self-assign decision roles, legacy user/role endpoints gone"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import login_and_activate


def _make_org(super_admin_client, tenant_id="acme", admin_email="admin@acme.test", pw="acme-admin-pw-1"):
    resp = super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant_id,
            "name": tenant_id,
            "admin_email": admin_email,
            "admin_display_name": f"{tenant_id} admin",
            "admin_password": pw,
        },
    )
    assert resp.status_code == 200, resp.text
    return admin_email, pw


def _org_client(admin_email, pw):
    from app.main import app

    client = TestClient(app)
    login_and_activate(client, admin_email, pw)
    return client


def test_org_admin_cannot_self_assign_a_decision_role(super_admin_client):
    email, pw = _make_org(super_admin_client)
    with _org_client(email, pw) as org:
        resp = org.post(
            "/api/org/role-assignments",
            json={"user_ref": email, "role": "governance_admin"},
        )
        assert resp.status_code == 403, resp.text
        assert "Segregation of duties" in resp.json()["detail"]


def test_admin_and_decision_roles_are_mutually_exclusive(super_admin_client):
    email, pw = _make_org(super_admin_client)
    with _org_client(email, pw) as org:
        # second user made a decision-maker
        org.post(
            "/api/org/users",
            json={"email": "reviewer@acme.test", "display_name": "Reviewer", "password": "reviewer-pw-1"},
        )
        granted = org.post(
            "/api/org/role-assignments",
            json={"user_ref": "reviewer@acme.test", "role": "governance_admin"},
        )
        assert granted.status_code == 200, granted.text

        # also making that decision-maker an org_admin must fail
        conflict = org.post(
            "/api/org/role-assignments",
            json={"user_ref": "reviewer@acme.test", "role": "org_admin"},
        )
        assert conflict.status_code == 409, conflict.text
        assert "Segregation of duties" in conflict.json()["detail"]


def test_org_admin_can_delegate_decision_roles_to_others(super_admin_client):
    email, pw = _make_org(super_admin_client)
    with _org_client(email, pw) as org:
        org.post(
            "/api/org/users",
            json={"email": "owner@acme.test", "display_name": "Owner", "password": "owner-pw-11111"},
        )
        resp = org.post(
            "/api/org/role-assignments",
            json={"user_ref": "owner@acme.test", "role": "risk_owner"},
        )
        assert resp.status_code == 200, resp.text


def test_legacy_governance_plane_user_endpoints_removed(super_admin_client):
    email, pw = _make_org(super_admin_client)
    with _org_client(email, pw) as org:
        # these endpoints allowed cross-tenant account overwrite and global
        # self-escalation; they are gone
        assert org.post("/api/users", json={"user_ref": "x", "display_name": "x"}).status_code == 404
        assert (
            org.post("/api/role-assignments", json={"user_ref": "x", "role": "governance_admin"}).status_code
            == 404
        )

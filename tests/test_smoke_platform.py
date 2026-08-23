"""Baseline smoke tests: the app boots, core auth works, ingestion accepts a batch.

These lock in current, correct behavior. Security-hardening PRs add their own
regression tests (which start red and go green) alongside the fix.
"""

from __future__ import annotations


def test_health_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "event_count" in resp.json()


def test_unauthenticated_reads_are_rejected(client):
    assert client.get("/api/applications").status_code == 401
    assert client.get("/api/compliance/aibom").status_code == 401


def test_default_super_admin_login(client):
    resp = client.post(
        "/api/auth/login",
        json={"email": "admin@norinth.local", "password": "norinth-admin"},
    )
    assert resp.status_code == 200
    user = resp.json()["user"]
    assert user["is_super_admin"] is True
    # The bootstrap admin is created with a forced password change.
    assert user["must_change_password"] is True


def test_bad_login_is_rejected(client):
    resp = client.post(
        "/api/auth/login",
        json={"email": "admin@norinth.local", "password": "wrong"},
    )
    assert resp.status_code == 401


def test_super_admin_cannot_read_tenant_governance(super_admin_client):
    # By design the platform super-admin plane has no tenant governance access.
    assert super_admin_client.get("/api/applications").status_code == 403


def test_super_admin_can_create_org_and_org_admin_can_login(super_admin_client):
    resp = super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "orgadmin@acme.test",
            "admin_display_name": "Org Admin",
            "admin_password": "acme-admin-pw-1",
        },
    )
    assert resp.status_code == 200, resp.text

    # Fresh client (no super-admin cookie) logging in as the org admin.
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as org_client:
        login = org_client.post(
            "/api/auth/login",
            json={"email": "orgadmin@acme.test", "password": "acme-admin-pw-1"},
        )
        assert login.status_code == 200, login.text
        assert login.json()["user"]["tenant_id"] == "acme"


def test_ingestion_accepts_a_batch(client):
    batch = {
        "events": [
            {
                "type": "model.call",
                "schema_version": "2026-01",
                "trace_id": "trc_smoke",
                "span_id": "spn_smoke",
                "timestamp": "2026-08-22T00:00:00Z",
                "service": "svc",
                "environment": "prod",
                "project": "p1",
                "attributes": {
                    "provider": "openai",
                    "model": "gpt-4o",
                    "operation": "chat",
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                    "metadata": {
                        # The dev ingestion key is bound to tenant-local; a batch
                        # claiming another tenant would be rejected (see C-1 tests).
                        "tenant_id": "tenant-local",
                        "application_name": "App",
                        "workflow_name": "wf",
                    },
                },
            }
        ]
    }
    resp = client.post(
        "/v1/events/batch",
        json=batch,
        headers={"Authorization": "Bearer dev"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1

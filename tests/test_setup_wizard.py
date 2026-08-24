"""first-run setup wizard api"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_setup_state_and_organization_flow(client, super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    # public, and true on a fresh install
    assert TestClient(app).get("/api/setup/state").json() == {"needs_setup": True}

    # only a super admin may run setup; anonymous gets 401
    payload = {"name": "Example Health", "admin_email": "Admin@ExampleHealth.org", "admin_display_name": "Dana", "admin_password": "a-long-password-123"}
    assert TestClient(app).post("/api/setup/organization", json=payload).status_code == 401

    created = super_admin_client.post("/api/setup/organization", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["organization"]["tenant_id"] == "example-health"  # slug from the name
    assert created.json()["org_admin_email"] == "admin@examplehealth.org"

    # setup complete: state flips, and the wizard endpoint refuses a second run
    assert TestClient(app).get("/api/setup/state").json() == {"needs_setup": False}
    assert super_admin_client.post("/api/setup/organization", json={**payload, "admin_email": "x@y.org"}).status_code == 409

    # operator signs in as the org admin with the chosen password, no forced rotation
    with TestClient(app) as org:
        login = org.post("/api/auth/login", json={"email": "admin@examplehealth.org", "password": "a-long-password-123"})
        assert login.status_code == 200
        assert login.json()["user"]["must_change_password"] is False
        assert "user.manage" in login.json()["user"]["permissions"]
        assert org.post("/api/ingestion-keys", json={"name": "first"}).status_code == 200

    # audit trail records provisioning via the wizard
    logs = super_admin_client.get("/api/audit-logs", params={"action": "org.provision"}).json()
    assert logs["page"]["total"] == 1


def test_setup_requires_admin_password_rotation_first(client):
    from tests.conftest import DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD

    # bootstrap admin on dev defaults still must rotate before provisioning
    login = client.post("/api/auth/login", json={"email": DEFAULT_ADMIN_EMAIL, "password": DEFAULT_ADMIN_PASSWORD})
    assert login.status_code == 200 and login.json()["user"]["must_change_password"] is True
    resp = client.post(
        "/api/setup/organization",
        json={"name": "Acme", "admin_email": "a@acme.test", "admin_display_name": "A", "admin_password": "a-long-password-123"},
    )
    assert resp.status_code == 403  # blocked by password-change middleware

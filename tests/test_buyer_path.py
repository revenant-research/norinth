"""public lead capture into the console and the org getting-started checklist"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def test_public_lead_is_captured_validated_rate_limited_and_visible_to_super_admin(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)  # anonymous visitor, super_admin_client is a separate signed-in session
    lead = {"name": "Dr. Test", "email": "Buyer@Example-Health.org", "organization": "Example Health", "interest": "pilot", "message": "ambient scribes"}
    created = client.post("/api/public/leads", json=lead)
    assert created.status_code == 201, created.text
    assert created.json()["lead_id"].startswith("lead_")

    # validate email shape and interest enum
    assert client.post("/api/public/leads", json={**lead, "email": "nope"}).status_code == 422
    assert client.post("/api/public/leads", json={**lead, "interest": "spam"}).status_code == 400

    # only platform admins see leads, tenant users and public do not
    assert client.get("/api/admin/leads").status_code in (401, 403)
    listing = super_admin_client.get("/api/admin/leads").json()
    assert listing["page"]["total"] == 1
    entry = listing["leads"][0]
    assert entry["email"] == "buyer@example-health.org"  # normalised
    assert entry["status"] == "new"

    # status moves through the funnel and is audit-logged
    moved = super_admin_client.post(f"/api/admin/leads/{entry['lead_id']}/status", json={"status": "contacted"})
    assert moved.status_code == 200 and moved.json()["lead"]["status"] == "contacted"
    assert super_admin_client.post(f"/api/admin/leads/{entry['lead_id']}/status", json={"status": "bogus"}).status_code == 400
    logs = super_admin_client.get("/api/audit-logs", params={"action": "lead.status"}).json()
    assert logs["page"]["total"] == 1

    # rate limit, one source address cannot flood the inbox
    for _ in range(9):
        client.post("/api/public/leads", json=lead)
    assert client.post("/api/public/leads", json=lead).status_code == 429


def test_onboarding_checklist_reflects_real_state(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test", "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    assert super_admin_client.get("/api/onboarding").status_code == 403  # organization view only
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        before = org.get("/api/onboarding").json()
        by_id = {s["id"]: s for s in before["steps"]}
        assert before["complete"] is False
        assert by_id["create_key"]["done"] is False
        assert by_id["send_events"]["done"] is False
        assert by_id["sign_evidence"]["optional"] is True

        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        event = {
            "type": "model.call", "schema_version": "2026-01", "trace_id": "t1", "span_id": "s1",
            "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
            "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 1, "output_tokens": 1},
                           "metadata": {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "wf"}},
        }
        assert org.post("/v1/events/batch", json={"events": [event]}, headers={"Authorization": f"Bearer {token}"}).status_code == 200
        org.get("/api/compliance/audit-packet")

        after = org.get("/api/onboarding").json()
        by_id = {s["id"]: s for s in after["steps"]}
        assert by_id["create_key"]["done"] is True
        assert by_id["send_events"]["done"] is True and "1 events" in by_id["send_events"]["detail"]
        assert by_id["first_system"]["done"] is True
        assert by_id["export_packet"]["done"] is True
        assert by_id["invite_reviewers"]["done"] is False  # only the admin exists
        assert after["completed"] > before["completed"]

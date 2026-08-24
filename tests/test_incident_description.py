"""an incident's description reaches the reviewer as text, not a digest

the sdk summarises values it captures, and for prompts and completions that
means a hash by default. an incident description is not model input or output:
it is written by a person for the governance record, so hashing it left the
dashboard and the audit packet holding a checksum instead of an account
"""

from __future__ import annotations

from tests.helpers import login_and_activate


def test_sdk_sends_the_description_as_readable_redacted_text():
    from norinth_logger.privacy import summarize_value

    # the shape client.incident() builds for the description attribute
    summary = summarize_value(
        "Adjusters report the summary omitted an escalation flag; contact ops@northwind.test.",
        True,
        None,
    )
    assert summary["content"].startswith("Adjusters report")
    assert "[redacted-email]" in summary["content"], summary
    assert "ops@northwind.test" not in summary["content"]


def test_platform_surfaces_the_description_on_the_incident(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient
    from norinth_logger.privacy import summarize_value

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        reported = "Adjusters report the summary omitted an escalation flag on three claims."
        event = {
            "type": "incident.event", "schema_version": "2026-01", "trace_id": "trc_i", "span_id": "spn_i",
            "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
            "status": "error",
            "attributes": {
                "incident_id": "inc-1", "title": "Copilot omitted an escalation flag",
                "severity": "High", "incident_status": "open",
                "description": summarize_value(reported, True, None),
                "metadata": {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"},
            },
        }
        assert org.post("/v1/events/batch", json={"events": [event]},
                        headers={"Authorization": f"Bearer {token}"}).status_code == 200

        incidents = org.get("/api/incidents").json()["incidents"]
        assert len(incidents) == 1, incidents
        assert incidents[0]["description"] == reported

        detail = org.get(f"/api/incidents/{incidents[0]['incident_id']}").json()
        record = detail.get("incident", detail)
        assert record["description"] == reported


def test_a_hash_only_description_does_not_break_the_record(super_admin_client):
    """older clients sent only a digest; the record must still load"""
    from app.main import app
    from fastapi.testclient import TestClient
    from norinth_logger.privacy import summarize_value

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        event = {
            "type": "incident.event", "schema_version": "2026-01", "trace_id": "trc_h", "span_id": "spn_h",
            "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
            "status": "error",
            "attributes": {
                "incident_id": "inc-2", "title": "Older client", "severity": "Low", "incident_status": "open",
                "description": summarize_value("hashed only", False, None),
                "metadata": {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"},
            },
        }
        assert org.post("/v1/events/batch", json={"events": [event]},
                        headers={"Authorization": f"Bearer {token}"}).status_code == 200
        incidents = org.get("/api/incidents").json()["incidents"]
        assert incidents[0]["description"] is None

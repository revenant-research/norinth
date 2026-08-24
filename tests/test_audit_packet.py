"""audit-ready evidence packet export"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def test_audit_packet_assembles_tenant_evidence(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    org.post(
        "/v1/events/batch",
        json={
            "events": [
                {
                    "type": "model.call",
                    "schema_version": "2026-01",
                    "trace_id": "t1",
                    "span_id": "s1",
                    "timestamp": "2026-08-22T00:00:00Z",
                    "service": "svc",
                    "environment": "prod",
                    "project": "p1",
                    "attributes": {
                        "provider": "openai",
                        "model": "gpt-4o",
                        "operation": "chat",
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                        "metadata": {"tenant_id": "acme", "application_name": "acme-app", "workflow_name": "wf"},
                    },
                }
            ]
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    packet = org.get("/api/compliance/audit-packet")
    assert packet.status_code == 200, packet.text
    body = packet.json()

    # structure and provenance
    assert body["tenant_id"] == "acme"
    assert body["generated_by"] == "oa@acme.test"
    assert body["packet_version"]
    for section in (
        "posture",
        "inventory",
        "control_assessments",
        "risk_findings",
        "governance_decisions",
        "deployment_gates",
        "incidents",
        "aibom",
        "audit_trail",
    ):
        assert section in body, f"packet missing {section}"

    # ingested telemetry shows up as evidence
    assert any(a.get("application_name") == "acme-app" for a in body["inventory"]["applications"])
    # audit trail integrity proven inside the packet
    assert body["audit_trail"]["integrity"]["ok"] is True

    org.close()


def test_audit_packet_requires_tenant_actor(super_admin_client):
    # super admin has no tenant scope so cannot pull a tenant packet
    resp = super_admin_client.get("/api/compliance/audit-packet")
    assert resp.status_code == 403

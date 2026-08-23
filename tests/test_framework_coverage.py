"""Test the per-framework coverage crosswalk (audit §6.2)."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def test_framework_coverage_rolls_up_control_assessments(super_admin_client):
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
    # A model.call satisfies the AI-INV-001 control (mapped to NIST AI RMF +
    # ISO/IEC 42001), so those frameworks should show partial coverage.
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

    resp = org.get("/api/compliance/framework-coverage")
    assert resp.status_code == 200, resp.text
    coverage = {c["framework"]: c for c in resp.json()["framework_coverage"]}

    # NIST AI RMF and ISO/IEC 42001 are present (they're cited by the seeded controls).
    assert "NIST AI RMF" in coverage
    assert "ISO/IEC 42001" in coverage

    nist = coverage["NIST AI RMF"]
    assert nist["total_requirements"] > 0
    # At least one requirement is satisfied (AI-INV-001 passed) and there are gaps
    # (controls with no runtime evidence yet).
    assert nist["satisfied"] >= 1
    assert 0 <= nist["coverage_pct"] <= 100
    assert isinstance(nist["gaps"], list)

    org.close()

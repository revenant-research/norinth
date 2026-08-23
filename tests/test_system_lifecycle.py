"""An AI system's stage is derived from its intake record and moves with the
intake review decision; inventory exposes stage and risk tier."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}


def test_stage_moves_discovered_to_in_review_to_approved(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test", "admin_display_name": "OA", "admin_password": "oa-password-1"})
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    call = {"type": "model.call", "schema_version": "2026-01", "trace_id": "t1", "span_id": "s1", "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
            "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 1, "output_tokens": 1}, "metadata": META}}
    assert org.post("/v1/events/batch", json={"events": [call]}, headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # Seen in telemetry, never registered: discovered (shadow AI).
    app_row = org.get("/api/applications").json()["applications"][0]
    assert app_row["stage"] == "discovered" and app_row["risk_tier"] is None

    # Registered through intake: in review, with a tier.
    submitted = org.post("/api/intake", json={"application_name": "Claims", "use_case": "Claims triage", "description": "d", "intended_purpose": "p", "data_sensitivity": "restricted", "autonomy_level": "supervised", "affects_individuals": True, "project": "p1", "environment": "prod"})
    assert submitted.status_code in (200, 201), submitted.text
    app_row = org.get("/api/applications").json()["applications"][0]
    assert app_row["stage"] == "in_review" and app_row["risk_tier"] in {"high", "critical"}

    # A reviewer (not the submitter) approves the intake review -> approved.
    org.post("/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev", "password": "rev-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "rev@acme.test", "role": "governance_reviewer"})
    task = next(t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "intake_review")
    with TestClient(app) as rev:
        login_and_activate(rev, "rev@acme.test", "rev-password-1")
        decided = rev.post("/api/decisions", json={"target_type": "review_task", "target_id": task["task_id"], "decision": "approve", "rationale": "fine"})
        assert decided.status_code == 200, decided.text
    app_row = org.get("/api/applications").json()["applications"][0]
    assert app_row["stage"] == "approved"
    detail = org.get(f"/api/applications/{app_row['entity_id']}").json()
    assert detail["application"]["stage"] == "approved"
    org.close()

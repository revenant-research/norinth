"""Regression test for decision-preserving derivation (audit B6).

A reviewer's decision on a risk finding (or a waived control) must survive the
governance re-computation that runs on every ingest, instead of being silently
reset to "open" / "passing".
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _model_call(span: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
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


def test_accepted_risk_is_not_reopened_on_reingest(super_admin_client):
    from app.main import app
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    # Provision org + a governance_admin (holds risk.accept), plus an ingest key.
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
    org.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]

    def ingest(span):
        return org.post(
            "/v1/events/batch", json={"events": [_model_call(span)]}, headers={"Authorization": f"Bearer {token}"}
        )

    # First ingest creates risk findings (e.g. missing guardrail/eval evidence).
    assert ingest("one").status_code == 200

    with connect() as connection:
        finding = connection.execute(
            "SELECT finding_id, status FROM risk_findings WHERE tenant_id = 'acme' LIMIT 1"
        ).fetchone()
    assert finding is not None, "expected at least one risk finding"
    assert finding["status"] == "open"
    finding_id = finding["finding_id"]

    # A reviewer accepts the risk.
    gov = TestClient(app)
    login_and_activate(gov, "gov@acme.test", "gov-password-1")
    decision = gov.post(
        "/api/decisions",
        json={
            "target_type": "risk_finding",
            "target_id": finding_id,
            "decision": "accept_risk",
            "rationale": "compensating controls in place",
        },
    )
    assert decision.status_code == 200, decision.text

    with connect() as connection:
        status_after_decision = connection.execute(
            "SELECT status FROM risk_findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()["status"]
    assert status_after_decision == "accepted"

    # A subsequent ingest re-runs the governance recompute. The accepted status
    # must NOT be reset to "open".
    assert ingest("two").status_code == 200
    with connect() as connection:
        status_after_reingest = connection.execute(
            "SELECT status FROM risk_findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()["status"]
    assert status_after_reingest == "accepted", "accepted risk was silently reopened by re-ingest (B6)"

    org.close()
    gov.close()

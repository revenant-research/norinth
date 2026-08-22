"""Regression tests for deployment-gate integrity (audit C-2).

Before this fix, a deployment gate with no blocking evidence was written
directly as "approved" (no human, no attribution), and the generic
/api/decisions route could flip a gate to "approved" while bypassing the
evidence guard. A release could ship with zero human sign-off.
"""

from __future__ import annotations

from tests.helpers import login_and_activate


def _deployment_event(tenant_id: str = "tenant-local") -> dict:
    return {
        "type": "deployment.event",
        "schema_version": "2026-01",
        "trace_id": "trc_dep",
        "span_id": "spn_dep",
        "timestamp": "2026-08-22T00:00:02Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "deployment_id": "dep-1",
            "version": "v1",
            "artifact_ref": "img:1",
            "provider": "openai",
            "model": "gpt-4o",
            "prompt_version": "v1",
            "deployment_status": "pending",
            "metadata": {
                "tenant_id": tenant_id,
                "application_name": "PayApp",
                "workflow_name": "wf",
            },
        },
    }


def test_gate_is_never_auto_approved(client):
    resp = client.post(
        "/v1/events/batch",
        json={"events": [_deployment_event()]},
        headers={"Authorization": "Bearer dev"},
    )
    assert resp.status_code == 200, resp.text

    from app.storage.raw_events import connect

    with connect() as connection:
        gates = connection.execute(
            "SELECT gate_status, actor_ref, decided_at FROM deployment_approval_gates"
        ).fetchall()
    assert len(gates) == 1
    gate = gates[0]
    # The system must never write an approved gate; it awaits a human decision
    # with no attribution yet.
    assert gate["gate_status"] == "pending_review"
    assert gate["actor_ref"] is None
    assert gate["decided_at"] is None


def test_decisions_route_cannot_transition_a_gate(super_admin_client):
    # A governance_admin in an org cannot use the generic /api/decisions route to
    # approve a gate — it must go through the guarded /approve endpoint.
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        org.post(
            "/api/org/users",
            json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"},
        )
        org.post(
            "/api/org/role-assignments",
            json={"user_ref": "gov@acme.test", "role": "governance_admin"},
        )

    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        # Even with gate.decide, the generic decisions route rejects gate/incident.
        gate_resp = gov.post(
            "/api/decisions",
            json={
                "target_type": "deployment_gate",
                "target_id": "any-gate-id",
                "decision": "approve",
                "rationale": "trying to bypass",
            },
        )
        assert gate_resp.status_code == 400, gate_resp.text
        assert "dedicated endpoint" in gate_resp.json()["detail"]

        incident_resp = gov.post(
            "/api/decisions",
            json={
                "target_type": "incident",
                "target_id": "any-incident-id",
                "decision": "close",
                "rationale": "trying to bypass",
            },
        )
        assert incident_resp.status_code == 400

"""remediating a gate's blockers is enough to approve it, with no new telemetry

the gate's blocker counts are stored on the row and only recomputed when
telemetry arrives. a reviewer who accepts the open findings and waives the
missing controls changes neither, so approval has to read live state or the
remediation the gate asks for can never clear it
"""

from __future__ import annotations

from tests.helpers import login_and_activate

META = {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"}


def _event(event_type: str, attributes: dict, span: str) -> dict:
    return {
        "type": event_type,
        "schema_version": "2026-01",
        "trace_id": "trc_gate",
        "span_id": span,
        "timestamp": "2026-08-22T00:00:02Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {**attributes, "metadata": META},
    }


def _full_evidence_batch() -> list[dict]:
    """a release with every piece of evidence the gate asks for"""
    return [
        _event("model.call", {"provider": "openai", "model": "gpt-4o",
                              "usage": {"input_tokens": 10, "output_tokens": 5}}, "spn_call"),
        _event("deployment.event", {"deployment_id": "dep-1", "version": "v1", "artifact_ref": "img:1",
                                    "provider": "openai", "model": "gpt-4o", "prompt_version": "v1",
                                    "deployment_status": "pending"}, "spn_dep"),
        _event("prompt.event", {"prompt_id": "pr-1", "version": "v1", "artifact_ref": "img:1",
                                "status": "active"}, "spn_prompt"),
        _event("eval.result", {"eval_id": "safety", "passed": True, "score": 0.97,
                               "prompt_version": "v1", "artifact_ref": "img:1"}, "spn_eval"),
    ]


def test_accepting_findings_and_waiving_controls_unblocks_the_gate(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        org.post("/api/org/users",
                 json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
        org.post("/api/org/role-assignments",
                 json={"user_ref": "gov@acme.test", "role": "governance_admin"})

        ingested = org.post("/v1/events/batch", json={"events": _full_evidence_batch()},
                            headers={"Authorization": f"Bearer {token}"})
        assert ingested.status_code == 200, ingested.text
        gates = org.get("/api/deployment-gates").json()["deployment_gates"]
        assert len(gates) == 1, gates
        gate_id = gates[0]["gate_id"]

    from app.storage.raw_events import connect

    with connect() as connection:
        findings = [row["finding_id"] for row in connection.execute(
            "SELECT finding_id FROM risk_findings WHERE status IN ('open', 'mitigation_required')"
        ).fetchall()]
        assessments = [row["assessment_id"] for row in connection.execute(
            "SELECT assessment_id FROM control_assessments WHERE status = 'missing'"
        ).fetchall()]
    # the fixture only matters if there is something to remediate
    assert findings or assessments

    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        blocked = gov.post(f"/api/deployment-gates/{gate_id}/approve",
                           json={"rationale": "approving before doing anything about the blockers"})
        assert blocked.status_code == 400, blocked.text

        for finding_id in findings:
            accepted = gov.post("/api/decisions", json={
                "target_type": "risk_finding", "target_id": finding_id, "decision": "accept_risk",
                "rationale": "accepted by the risk owner with compensating controls recorded",
            })
            assert accepted.status_code == 200, accepted.text
        for assessment_id in assessments:
            waived = gov.post("/api/decisions", json={
                "target_type": "control_assessment", "target_id": assessment_id, "decision": "waive",
                "rationale": "waived pending the control rollout, tracked by the control owner",
            })
            assert waived.status_code == 200, waived.text

        # no further telemetry: remediation alone has to be enough
        approved = gov.post(f"/api/deployment-gates/{gate_id}/approve",
                            json={"rationale": "every finding accepted and every missing control waived"})
        assert approved.status_code == 200, approved.text
        assert approved.json()["deployment_gate"]["gate_status"] == "approved"

        # and the reviewer is not left reading blockers that no longer exist
        detail = gov.get(f"/api/deployment-gates/{gate_id}").json()
        gate = detail.get("deployment_gate", detail)
        assert int(gate["risk_count"]) == 0
        assert int(gate["missing_control_count"]) == 0

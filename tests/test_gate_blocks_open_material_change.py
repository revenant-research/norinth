"""an open material change blocks gate approval, like open risks and controls

gate_required_reason surfaces open material changes to the reviewer as a blocker,
and gate_evidence_counts counts them, but approval must actually enforce it:
shipping a build whose material surface changed without anyone reviewing the
change is exactly what the gate exists to stop
"""

from __future__ import annotations

from tests.helpers import login_and_activate

META = {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"}


def _event(event_type: str, attributes: dict, span: str, model: str = "gpt-4o") -> dict:
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


def _material_change_batch() -> list[dict]:
    """a later model.call on a new model shifts the app's material surface"""
    return [
        _event("model.call", {"provider": "openai", "model": "gpt-4o-mini",
                              "usage": {"input_tokens": 3, "output_tokens": 2}}, "spn_call2"),
    ]


def test_open_material_change_blocks_approval_until_reviewed(super_admin_client):
    from app.main import app
    from app.storage.raw_events import connect
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

        # a release with full evidence, then a material change to its model surface
        assert org.post("/v1/events/batch", json={"events": _full_evidence_batch()},
                        headers={"Authorization": f"Bearer {token}"}).status_code == 200
        assert org.post("/v1/events/batch", json={"events": _material_change_batch()},
                        headers={"Authorization": f"Bearer {token}"}).status_code == 200
        gates = org.get("/api/deployment-gates").json()["deployment_gates"]
        assert len(gates) == 1, gates
        gate_id = gates[0]["gate_id"]

    # remediate every other blocker so the material change is the only one left
    with connect() as connection:
        findings = [r["finding_id"] for r in connection.execute(
            "SELECT finding_id FROM risk_findings WHERE status IN ('open', 'mitigation_required')").fetchall()]
        assessments = [r["assessment_id"] for r in connection.execute(
            "SELECT assessment_id FROM control_assessments WHERE status = 'missing'").fetchall()]
        open_changes = [r["change_id"] for r in connection.execute(
            "SELECT change_id FROM change_events WHERE status = 'open'").fetchall()]
    # the test is only meaningful if a material change actually exists
    assert open_changes, "expected an open material change from the model shift"

    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        for finding_id in findings:
            assert gov.post("/api/decisions", json={
                "target_type": "risk_finding", "target_id": finding_id, "decision": "accept_risk",
                "rationale": "accepted by the risk owner with compensating controls recorded",
            }).status_code == 200
        for assessment_id in assessments:
            assert gov.post("/api/decisions", json={
                "target_type": "control_assessment", "target_id": assessment_id, "decision": "waive",
                "rationale": "waived pending the control rollout, tracked by the control owner",
            }).status_code == 200

        # risks and controls are clear, but the material change is still open
        blocked = gov.post(f"/api/deployment-gates/{gate_id}/approve",
                           json={"rationale": "approving with the model change still unreviewed"})
        assert blocked.status_code == 400, blocked.text
        assert "material change" in blocked.json()["detail"].lower()

        # review the material change, then the gate can be approved
        for change_id in open_changes:
            assert gov.post("/api/decisions", json={
                "target_type": "change_event", "target_id": change_id, "decision": "approve",
                "rationale": "the model addition was reviewed and is acceptable for this release",
            }).status_code == 200

        approved = gov.post(f"/api/deployment-gates/{gate_id}/approve",
                            json={"rationale": "every blocker remediated, including the reviewed model change"})
        assert approved.status_code == 200, approved.text
        assert approved.json()["deployment_gate"]["gate_status"] == "approved"

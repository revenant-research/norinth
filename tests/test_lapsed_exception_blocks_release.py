"""a lapsed exception stops counting as remediation, without waiting for telemetry

exceptions are only expired while ingesting a batch, so in a quiet environment a
risk acceptance that has passed its expiry date stayed active, its finding stayed
waived, and a release could be approved on the strength of it
"""

from __future__ import annotations

from tests.helpers import login_and_activate

META = {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"}


def _event(event_type: str, attributes: dict, span: str) -> dict:
    return {
        "type": event_type,
        "schema_version": "2026-01",
        "trace_id": "trc_exc",
        "span_id": span,
        "timestamp": "2026-08-22T00:00:02Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {**attributes, "metadata": META},
    }


def _release_with_full_evidence() -> list[dict]:
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


def test_release_is_blocked_once_the_covering_exception_has_lapsed(super_admin_client):
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
        ingested = org.post("/v1/events/batch", json={"events": _release_with_full_evidence()},
                            headers={"Authorization": f"Bearer {token}"})
        assert ingested.status_code == 200, ingested.text
        gate_id = org.get("/api/deployment-gates").json()["deployment_gates"][0]["gate_id"]

    with connect() as connection:
        findings = [row["finding_id"] for row in connection.execute(
            "SELECT finding_id FROM risk_findings WHERE status IN ('open', 'mitigation_required')"
        ).fetchall()]
        assessments = [row["assessment_id"] for row in connection.execute(
            "SELECT assessment_id FROM control_assessments WHERE status = 'missing'"
        ).fetchall()]
    assert findings

    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        # one finding is accepted under a time-boxed exception, the rest cleared outright
        waived = gov.post("/api/exceptions", json={
            "target_type": "risk_finding", "target_id": findings[0],
            "reason": "accepted for the quarter while the fix is scheduled",
            "compensating_control": "weekly manual review by the claims lead",
            "expires_at": "2099-12-31",
        })
        assert waived.status_code == 200, waived.text
        for finding_id in findings[1:]:
            gov.post("/api/decisions", json={
                "target_type": "risk_finding", "target_id": finding_id, "decision": "accept_risk",
                "rationale": "accepted by the risk owner with compensating controls recorded",
            })
        for assessment_id in assessments:
            gov.post("/api/decisions", json={
                "target_type": "control_assessment", "target_id": assessment_id, "decision": "waive",
                "rationale": "waived pending the control rollout, tracked by the control owner",
            })

        # while the exception holds, the release is approvable
        detail = gov.get(f"/api/deployment-gates/{gate_id}").json()
        gate = detail.get("deployment_gate", detail)
        assert int(gate["risk_count"]) == 0

        # the expiry date arrives; no telemetry is ingested in the meantime
        with connect() as connection:
            connection.execute(
                "UPDATE governance_exceptions SET expires_at = '2000-01-01' WHERE target_id = ?",
                (findings[0],),
            )

        blocked = gov.post(f"/api/deployment-gates/{gate_id}/approve",
                           json={"rationale": "approving even though the covering exception has lapsed"})
        assert blocked.status_code == 400, blocked.text
        assert "risk findings are open" in blocked.json()["detail"]

        # and the lapsed exception is not still presented as active
        listed = gov.get("/api/exceptions").json()["exceptions"]
        assert all(item["status"] != "active" for item in listed if item["target_id"] == findings[0])

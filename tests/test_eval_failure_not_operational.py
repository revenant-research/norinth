"""a failed eval is a quality finding, not an operational one

eval.result carries status "error" when the eval did not pass. that status is
the eval's verdict, not a runtime failure, so it must raise RISK-EVL-002
(failed evaluation) and leave RISK-OPS-001 (operational reliability) alone.
the register finding keeps the release gate blocked exactly as before, under
the right name. a model call that errors must still raise RISK-OPS-001. both
the ingest fold path and the full rebuild path are covered.
"""

from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant,
            "name": tenant,
            "admin_email": f"a@{tenant}.test",
            "admin_display_name": "A",
            "admin_password": f"{tenant}-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, {"Authorization": f"Bearer {token}"}


def _event(tenant: str, span: str, event_type: str, status: str, attributes: dict) -> dict:
    return {
        "type": event_type,
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "name": span,
        "status": status,
        "attributes": {
            **attributes,
            "metadata": {"tenant_id": tenant, "application_name": f"{tenant}-app", "workflow_name": "wf"},
        },
    }


def _model_call(tenant: str, span: str, status: str = "success") -> dict:
    return _event(
        tenant,
        span,
        "model.call",
        status,
        {"provider": "openai", "model": "gpt-4o", "operation": "chat", "usage": {"input_tokens": 1, "output_tokens": 1}},
    )


def _failed_eval(tenant: str, span: str) -> dict:
    # the shape the SDK's eval_result emitter produces for passed=False
    return _event(
        tenant,
        span,
        "eval.result",
        "error",
        {"eval_name": "faithfulness", "score": 0.4, "threshold": 0.8, "passed": False},
    )


def _rule_ids(org) -> set[str]:
    return {r.get("rule_id") for r in org.get("/api/risk-register").json()["risks"]}


def _finding(org, rule_id: str) -> dict | None:
    return next((r for r in org.get("/api/risk-register").json()["risks"] if r.get("rule_id") == rule_id), None)


def test_failed_eval_does_not_raise_operational_finding(super_admin_client):
    org, headers = _org(super_admin_client, "evalfail")
    batch = [_model_call("evalfail", "m1"), _failed_eval("evalfail", "e1")]
    assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200

    assert "RISK-OPS-001" not in _rule_ids(org), "a failed eval was reported as an operational failure"
    finding = _finding(org, "RISK-EVL-002")
    assert finding is not None, "the failed eval must still be a register finding"
    assert finding["status"] == "open"
    assert finding["evidence_trace_ids"] == ["trc_e1"]
    assert finding["evidence_summary"] == "1 evaluation result(s) below threshold"
    org.close()


def test_failed_eval_does_not_raise_operational_finding_on_rebuild(super_admin_client):
    org, headers = _org(super_admin_client, "evalrebuild")
    batch = [_model_call("evalrebuild", "m1"), _failed_eval("evalrebuild", "e1")]
    assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200

    from app.storage.governance_policy import refresh_governance_assessments

    refresh_governance_assessments()
    assert "RISK-OPS-001" not in _rule_ids(org), "the rebuild path counted a failed eval as an operational failure"
    finding = _finding(org, "RISK-EVL-002")
    assert finding is not None
    assert finding["evidence_trace_ids"] == ["trc_e1"]
    org.close()


def test_passing_eval_raises_no_eval_finding(super_admin_client):
    org, headers = _org(super_admin_client, "evalpass")
    passing = _event(
        "evalpass", "e1", "eval.result", "success",
        {"eval_name": "faithfulness", "score": 0.9, "threshold": 0.8, "passed": True},
    )
    batch = [_model_call("evalpass", "m1"), passing]
    assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200
    assert "RISK-EVL-002" not in _rule_ids(org)
    org.close()


def test_failed_model_call_still_raises_operational_finding(super_admin_client):
    org, headers = _org(super_admin_client, "opsfail")
    batch = [_model_call("opsfail", "m1", status="error"), _failed_eval("opsfail", "e1")]
    assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200

    risks = [r for r in org.get("/api/risk-register").json()["risks"] if r.get("rule_id") == "RISK-OPS-001"]
    assert len(risks) == 1
    assert risks[0]["evidence_summary"] == "1 error events observed", "the failed eval was counted as an error"
    assert risks[0]["evidence_trace_ids"] == ["trc_m1"]

    from app.storage.governance_policy import refresh_governance_assessments

    refresh_governance_assessments()
    risks = [r for r in org.get("/api/risk-register").json()["risks"] if r.get("rule_id") == "RISK-OPS-001"]
    assert risks[0]["evidence_summary"] == "1 error events observed"
    assert risks[0]["evidence_trace_ids"] == ["trc_m1"]
    org.close()

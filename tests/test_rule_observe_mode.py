"""a new risk rule can run in observe mode before it blocks releases

every open finding counts toward a release gate, so a new custom rule used to
block every release from the moment it was added. a tenant's own rule can now
start in observe mode: its findings have status "observed", appear in the
register, and do not count toward gates, framework gaps or owner routing.
promoting it to enforce reopens those findings at once and is audited.
built-in rules always enforce, and an enforced rule cannot return to observe
"""

from __future__ import annotations

import json
import pathlib
import sys
from datetime import UTC, datetime

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

TENANT = "obs"
META = {"tenant_id": TENANT, "application_name": "claims", "workflow_name": "triage"}
REF = "NIST AI RMF MAP 4.2"


@pytest.fixture
def org(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": TENANT,
            "name": TENANT,
            "admin_email": f"a@{TENANT}.test",
            "admin_display_name": "A",
            "admin_password": f"{TENANT}-admin-pw-1",
        },
    )
    client = TestClient(app)
    login_and_activate(client, f"a@{TENANT}.test", f"{TENANT}-admin-pw-1")
    token = client.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    try:
        yield client, {"Authorization": f"Bearer {token}"}
    finally:
        client.close()


def _rule(mode: str | None = None, rule_id: str = "OBS-VENDOR-1") -> dict:
    body = {
        "rule_id": rule_id,
        "name": "Any third-party provider",
        "signal": "provider_dependency",
        "severity": "High",
        "framework_refs": [REF],
        "rationale": "Trial rule for third-party model use.",
    }
    if mode is not None:
        body["mode"] = mode
    return body


def _event(event_type: str, span: str, attributes: dict) -> dict:
    return {
        "type": event_type,
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {**attributes, "metadata": META},
    }


def _model_call(span: str) -> dict:
    return _event("model.call", span, {"provider": "openai", "model": "gpt-4o", "operation": "chat"})


def _finding(client, rule_id: str = "OBS-VENDOR-1") -> dict | None:
    risks = client.get("/api/risk-register").json()["risks"]
    return next((r for r in risks if r["rule_id"] == rule_id), None)


def _gate_risk_count(tenant_id: str = TENANT) -> int:
    from app.storage.deployments import count_scoped
    from app.storage.raw_events import connect

    params = {"tenant_id": tenant_id, "project": "p1", "environment": "prod", "application_name": "claims"}
    with connect() as connection:
        return count_scoped(connection, "risk_findings", "status IN ('open', 'mitigation_required')", params)


def _gaps(client) -> list[str]:
    families = client.get("/api/compliance/framework-coverage").json()["framework_coverage"]
    return next(entry for entry in families if entry["framework"] == "NIST AI RMF")["gaps"]


def test_observed_findings_are_visible_but_do_not_block(org):
    client, headers = org
    created = client.post("/api/risk-rules", json=_rule("observe"))
    assert created.status_code == 200, created.text
    assert created.json()["risk_rule"]["mode"] == "observe"
    assert client.post("/v1/events/batch", json={"events": [_model_call("m1")]}, headers=headers).status_code == 200

    finding = _finding(client)
    assert finding is not None, "an observe-mode rule still raises a visible finding"
    assert finding["status"] == "observed"
    blocking_before = _gate_risk_count()
    assert REF not in _gaps(client), "an observed finding must not mark its requirement as a gap"

    # the built-in provider rule's open finding is the only blocker from this traffic
    assert _finding(client, "RISK-TPD-001")["status"] == "open"
    assert blocking_before == len([r for r in client.get("/api/risk-register").json()["risks"] if r["status"] == "open"])


def test_promotion_reopens_findings_and_is_audited(org):
    client, headers = org
    assert client.post("/api/risk-rules", json=_rule("observe")).status_code == 200
    assert client.post("/v1/events/batch", json={"events": [_model_call("m1")]}, headers=headers).status_code == 200
    before = _gate_risk_count()

    promoted = client.post("/api/risk-rules", json=_rule("enforce"))
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["risk_rule"]["reopened_findings"] == 1
    assert _finding(client)["status"] == "open", "promotion must not wait for the next telemetry"
    assert _gate_risk_count() == before + 1
    assert REF in _gaps(client)

    # later telemetry keeps it open under the enforced rule
    assert client.post("/v1/events/batch", json={"events": [_model_call("m2")]}, headers=headers).status_code == 200
    assert _finding(client)["status"] == "open"

    entries = client.get("/api/audit-logs?action=risk_rule.promote").json()["audit_logs"]
    assert len(entries) == 1
    detail = entries[0]["detail"] if isinstance(entries[0]["detail"], dict) else json.loads(entries[0]["detail"])
    assert (detail["previous_mode"], detail["mode"], detail["reopened_findings"]) == ("observe", "enforce", 1)


def test_rules_enforce_by_default(org):
    client, headers = org
    created = client.post("/api/risk-rules", json=_rule())
    assert created.status_code == 200, created.text
    assert created.json()["risk_rule"]["mode"] == "enforce"
    assert client.post("/v1/events/batch", json={"events": [_model_call("m1")]}, headers=headers).status_code == 200
    assert _finding(client)["status"] == "open"
    listed = {r["rule_id"]: r for r in client.get("/api/risk-rules").json()["risk_rules"]}
    assert listed["OBS-VENDOR-1"]["mode"] == "enforce"
    assert listed["RISK-CTL-001"]["mode"] == "enforce"


def test_an_enforced_rule_cannot_return_to_observe(org):
    client, _ = org
    assert client.post("/api/risk-rules", json=_rule("enforce")).status_code == 200
    refused = client.post("/api/risk-rules", json=_rule("observe"))
    assert refused.status_code == 400
    assert "cannot return to observe mode" in refused.json()["detail"]
    listed = {r["rule_id"]: r for r in client.get("/api/risk-rules").json()["risk_rules"]}
    assert listed["OBS-VENDOR-1"]["mode"] == "enforce"


def test_built_in_rules_cannot_observe(org):
    client, _ = org
    for rule_id in ("RISK-CTL-001", "RISK-AGT-TRIFECTA", "RISK-VND-001"):
        refused = client.post("/api/risk-rules", json=_rule("observe", rule_id=rule_id))
        assert refused.status_code == 400, rule_id
        assert "built-in rules always enforce" in refused.json()["detail"]
    assert client.post("/api/risk-rules", json=_rule("sometimes")).status_code == 400


def test_observed_findings_are_not_routed_to_owners(org):
    client, headers = org
    assert client.post("/api/risk-rules", json=_rule("observe")).status_code == 200
    assert client.post("/v1/events/batch", json={"events": [_model_call("m1")]}, headers=headers).status_code == 200
    from app.storage.raw_events import connect
    from app.storage.workflow import refresh_workflow_state, upsert_owner_policy

    upsert_owner_policy(
        {"policy_id": "route-findings", "subject_type": "risk_finding", "owner_role": "risk_owner", "source": "test"},
        TENANT,
    )
    refresh_workflow_state()

    def routed(finding_id: str) -> int:
        with connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM owner_assignments WHERE subject_type = 'risk_finding' AND subject_name = ?",
                (finding_id,),
            ).fetchone()
        return int(row["n"])

    assert routed(_finding(client, "RISK-TPD-001")["finding_id"]) == 1, "the policy routes open findings"
    assert routed(_finding(client)["finding_id"]) == 0, "an observed finding is not routed to an owner"


def test_rebuild_path_keeps_the_observed_status(org):
    client, headers = org
    assert client.post("/api/risk-rules", json=_rule("observe")).status_code == 200
    assert client.post("/v1/events/batch", json={"events": [_model_call("m1")]}, headers=headers).status_code == 200
    from app.storage.governance_policy import refresh_governance_assessments

    refresh_governance_assessments()
    assert _finding(client)["status"] == "observed"

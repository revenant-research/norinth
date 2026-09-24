"""controls report coverage of recent traffic and the age of their evidence

a control used to pass once any single qualifying event arrived, and stay
passing. it still does, but each assessment now also reports the share of the
application's traces in the coverage window that carried qualifying evidence,
and whether the latest evidence is older than the stale age. the governance
policy can set a minimum coverage per environment, which the release gate
enforces; with no minimum (the default) the gate behaves as before
"""

from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime, timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

TENANT = "cov"
META = {"tenant_id": TENANT, "application_name": "claims", "workflow_name": "triage", "user_id": "u1"}


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


def _at(days_ago: float = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()


def _event(event_type: str, trace: str, attributes: dict, *, days_ago: float = 0, metadata: dict | None = None) -> dict:
    return {
        "type": event_type,
        "schema_version": "2026-01",
        "trace_id": f"trc_{trace}",
        "span_id": f"spn_{trace}_{event_type}",
        "timestamp": _at(days_ago),
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {**attributes, "metadata": metadata if metadata is not None else META},
    }


def _model_call(trace: str, **kwargs) -> dict:
    return _event(
        "model.call",
        trace,
        {"provider": "openai", "model": "gpt-4o", "operation": "chat", "prompt": {"hash": "h"}, "response": {"hash": "h"}},
        **kwargs,
    )


def _guardrail(trace: str, **kwargs) -> dict:
    return _event("guardrail.decision", trace, {"guardrail_name": "pii", "decision": "allow", "matched_rules": ["r1"]}, **kwargs)


def _send(client, headers, events: list[dict]) -> None:
    resp = client.post("/v1/events/batch", json={"events": events}, headers=headers)
    assert resp.status_code == 200, resp.text


def _controls(client) -> dict[str, dict]:
    rows = client.get("/api/control-evidence").json()["controls"]
    return {row["control_id"]: row for row in rows if row["application_name"] == "claims"}


def _activate(client, body: dict, activator=None) -> None:
    draft = client.post("/api/governance-policy/draft", json={"body": body})
    assert draft.status_code == 200, draft.text
    version = draft.json()["policy"]["version"]
    activated = (activator or client).post(f"/api/governance-policy/versions/{version}/activate")
    assert activated.status_code == 200, activated.text


def _second_admin(client):
    """a second config.write holder, needed to activate a loosening policy"""
    from app.main import app
    from fastapi.testclient import TestClient

    client.post("/api/org/users", json={"email": f"b@{TENANT}.test", "display_name": "B", "password": "b-password-1234"})
    client.post("/api/org/role-assignments", json={"user_ref": f"b@{TENANT}.test", "role": "org_admin"})
    second = TestClient(app)
    login_and_activate(second, f"b@{TENANT}.test", "b-password-1234")
    return second


def test_guardrail_coverage_is_the_share_of_model_call_traces(org):
    client, headers = org
    _send(client, headers, [_model_call(f"t{i}") for i in range(4)] + [_guardrail("t0")])

    guardrail = _controls(client)["AI-GRD-001"]
    assert guardrail["status"] == "passing", "one guardrail event still marks the control passing"
    coverage = guardrail["coverage"]
    assert coverage["basis_event_types"] == ["model.call"]
    assert (coverage["basis_traces"], coverage["covered_traces"], coverage["coverage_pct"]) == (4, 1, 25.0)
    assert coverage["window_days"] == 7
    assert coverage["stale"] is False

    # evidence for an earlier trace arriving in a later batch still counts
    _send(client, headers, [_guardrail("t1")])
    coverage = _controls(client)["AI-GRD-001"]["coverage"]
    assert (coverage["covered_traces"], coverage["coverage_pct"]) == (2, 50.0)


def test_completeness_controls_measure_their_own_events(org):
    client, headers = org
    no_workflow = {key: value for key, value in META.items() if key != "workflow_name"}
    events = [_model_call(f"t{i}") for i in range(4)] + [_model_call("t4", metadata=no_workflow)]
    _send(client, headers, events)
    inventory = _controls(client)["AI-INV-001"]["coverage"]
    assert inventory["basis_event_types"] == ["model.call"]
    assert (inventory["basis_traces"], inventory["covered_traces"], inventory["coverage_pct"]) == (5, 4, 80.0)


def test_traffic_outside_the_window_is_not_counted(org):
    client, headers = org
    _send(client, headers, [_model_call("old", days_ago=10), _model_call("new"), _guardrail("new")])
    coverage = _controls(client)["AI-GRD-001"]["coverage"]
    assert (coverage["basis_traces"], coverage["covered_traces"], coverage["coverage_pct"]) == (1, 1, 100.0)


def test_no_traffic_in_the_window_has_no_coverage_figure(org):
    client, headers = org
    _send(client, headers, [_model_call("old", days_ago=10), _guardrail("old", days_ago=10)])
    coverage = _controls(client)["AI-GRD-001"]["coverage"]
    assert coverage["basis_traces"] == 0
    assert coverage["coverage_pct"] is None


def test_evidence_older_than_the_stale_age_is_stale(org):
    client, headers = org
    _send(client, headers, [_model_call("t0", days_ago=40), _guardrail("t0", days_ago=40)])
    guardrail = _controls(client)["AI-GRD-001"]
    assert guardrail["status"] == "passing"
    assert guardrail["coverage"]["stale"] is True
    assert guardrail["coverage"]["stale_after_days"] == 30

    # a longer stale age loosens the policy, so a second administrator activates it
    with _second_admin(client) as second:
        _activate(
            client,
            {"schema": "governance-policy/v1", "evidence": {"stale_after_days": 60, "coverage_window_days": 14}},
            activator=second,
        )
    coverage = _controls(client)["AI-GRD-001"]["coverage"]
    assert coverage["stale"] is False
    assert coverage["stale_after_days"] == 60
    assert coverage["window_days"] == 14


def _deployment() -> dict:
    return _event(
        "deployment.event",
        "dep",
        {
            "deployment_id": "dep-1",
            "version": "v1",
            "artifact_ref": "img:v1",
            "provider": "openai",
            "model": "gpt-4o",
            "prompt_version": "p1",
            "deployment_status": "pending",
            "deployed_by": "ci@cov.test",
        },
    )


def _gate(client) -> dict:
    gates = client.get("/api/deployment-gates").json()["deployment_gates"]
    assert len(gates) == 1, gates
    return gates[0]


def test_gate_counts_controls_below_the_policy_minimum(org):
    client, headers = org
    _send(client, headers, [_model_call(f"t{i}") for i in range(4)] + [_guardrail("t0"), _deployment()])
    gate = _gate(client)
    assert gate["undercovered_control_count"] == 0, "with no minimum the gate does not look at coverage"
    assert "coverage" not in gate["required_reason"]

    _activate(
        client,
        {"schema": "governance-policy/v1", "gates": {"environments": {"prod": {"min_control_coverage": 50}}}},
    )
    _send(client, headers, [_model_call("t9")])  # any new telemetry refreshes the stored gate
    gate = _gate(client)
    # guardrails cover 1 of 5 traces; every other control covers all of them
    assert gate["undercovered_control_count"] == 1
    assert "1 controls below 50% coverage" in gate["required_reason"]


def test_gate_approval_refuses_undercovered_controls(fresh_db, monkeypatch):
    from app.storage import deployments

    evidence = {
        "risk_count": 0,
        "missing_control_count": 0,
        "material_change_count": 0,
        "max_open_material_changes": 0,
        "prompt_version_id": "pv",
        "prompt_evidence_status": "linked",
        "passing_eval_count": 1,
        "require_attested_evals": False,
        "min_control_coverage": 90.0,
        "undercovered_control_count": 2,
        "policy_tenant": "",
        "policy_version": 1,
    }
    monkeypatch.setattr(deployments, "live_gate_evidence", lambda connection, gate: evidence)
    with deployments.connect() as connection:
        connection.execute(
            """
            INSERT INTO deployment_approval_gates (
                gate_id, deployment_id, version_id, tenant_id, project, environment, application_name,
                workflow_name, gate_status, required_reason, risk_count, missing_control_count,
                material_change_count, submitted_at, updated_at
            )
            VALUES ('g1', 'd1', 'v1', 't', 'p', 'prod', 'a', 'w', 'pending_review', '', 0, 0, 0,
                    datetime('now'), datetime('now'))
            """
        )
    with pytest.raises(deployments.DomainError, match="2 controls cover less than 90% of recent traffic"):
        deployments.set_deployment_gate_status("g1", "approved", "reviewer@t.test", "Reviewed the release evidence.")


def test_refolding_the_same_evidence_does_not_change_coverage(org):
    client, headers = org
    _send(client, headers, [_model_call("t0"), _model_call("t1"), _guardrail("t0")])
    from app.storage.governance_policy import list_control_library, record_control_evidence
    from app.storage.raw_events import connect

    app_context = {"tenant_id": TENANT, "project": "p1", "environment": "prod", "application_name": "claims"}
    with connect() as connection:
        control = next(c for c in list_control_library(connection, TENANT) if c["control_id"] == "AI-GRD-001")
        for _ in range(3):
            record_control_evidence(connection, app_context, control, [_guardrail("t0")])
    coverage = _controls(client)["AI-GRD-001"]["coverage"]
    assert (coverage["basis_traces"], coverage["covered_traces"]) == (2, 1)


def test_upgrade_backfills_existing_evidence(org):
    client, headers = org
    _send(client, headers, [_model_call("t0", days_ago=2), _model_call("t1", days_ago=2), _guardrail("t0", days_ago=2)])
    from app.storage.migrations import _0025_control_coverage
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute("DELETE FROM control_evidence_traces")
    assert _controls(client)["AI-GRD-001"]["coverage"]["stale"] is True
    with connect() as connection:
        _0025_control_coverage(connection)
    coverage = _controls(client)["AI-GRD-001"]["coverage"]
    assert (coverage["basis_traces"], coverage["covered_traces"], coverage["stale"]) == (2, 1, False)


def test_erasing_an_organization_removes_its_evidence_traces(org):
    client, headers = org
    _send(client, headers, [_model_call("t0"), _guardrail("t0")])
    from app.storage.raw_events import connect
    from app.storage.retention import purge_tenant_data

    purge_tenant_data(TENANT)
    with connect() as connection:
        remaining = connection.execute(
            "SELECT COUNT(*) AS n FROM control_evidence_traces WHERE tenant_id = ?", (TENANT,)
        ).fetchone()
    assert int(remaining["n"]) == 0


def test_policy_settings_are_validated_and_loosening_is_detected(fresh_db):
    from app.storage.policy_engine import DEFAULT_POLICY_BODY, policy_loosening, validate_policy_body

    def body(**sections):
        return {"schema": "governance-policy/v1", **sections}

    assert validate_policy_body(body(evidence={"coverage_window_days": 31}))
    assert validate_policy_body(body(evidence={"stale_after_days": 0}))
    assert validate_policy_body(body(evidence={"unknown": 1}))
    assert validate_policy_body(body(gates={"environments": {"prod": {"min_control_coverage": 101}}}))
    assert validate_policy_body(body(gates={"environments": {"prod": {"min_control_coverage": True}}}))
    assert validate_policy_body(body(evidence={"coverage_window_days": 14, "stale_after_days": 90})) == []
    assert validate_policy_body(body(gates={"environments": {"prod": {"min_control_coverage": 95.5}}})) == []

    strict = body(gates={"environments": {"prod": {"min_control_coverage": 90}}}, evidence={"stale_after_days": 14})
    relaxed = body(gates={"environments": {"prod": {"min_control_coverage": 50}}}, evidence={"stale_after_days": 60})
    assert policy_loosening(strict, relaxed, DEFAULT_POLICY_BODY) == [
        "gates.environments.prod: the minimum control coverage is lower",
        "evidence: controls stay fresh longer before they are marked stale",
    ]
    assert policy_loosening(relaxed, strict, DEFAULT_POLICY_BODY) == []
    assert policy_loosening(body(), body(evidence={"coverage_window_days": 30}), DEFAULT_POLICY_BODY) == [
        "evidence: coverage is measured over a longer window"
    ]

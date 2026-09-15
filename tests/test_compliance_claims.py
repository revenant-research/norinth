"""the compliance page's claims are backed by code

three claims the F500 evaluation found untrue: the nav promises OWASP
coverage but coverage was built only from the control library (OWASP refs
live on detection rules); the system hub says a retired system's telemetry
"is a finding" but no code path produced one; and the per-tenant audit
packet reported the platform-wide audit row count.
"""

from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime, timedelta

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


def _gov_user(org, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    org.post("/api/org/users", json={"email": f"gov@{tenant}.test", "display_name": "Gov", "password": "gov-password-12"})
    org.post("/api/org/role-assignments", json={"user_ref": f"gov@{tenant}.test", "role": "governance_admin"})
    gov = TestClient(app)
    login_and_activate(gov, f"gov@{tenant}.test", "gov-password-12")
    return gov


def _model_call(tenant: str, span: str, timestamp: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": timestamp,
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "provider": "openai",
            "model": "gpt-4o",
            "operation": "chat",
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "metadata": {"tenant_id": tenant, "application_name": f"{tenant}-app", "workflow_name": "wf"},
        },
    }


def _coverage(org) -> dict[str, dict]:
    body = org.get("/api/compliance/framework-coverage").json()
    return {entry["framework"]: entry for entry in body["framework_coverage"]}


def test_owasp_agentic_family_appears_in_coverage(super_admin_client):
    """the nav promises OWASP; the agentic detection rules map it, so coverage
    must include it rather than silently dropping the family"""
    org, _ = _org(super_admin_client, "acme")
    families = _coverage(org)
    owasp = next((entry for name, entry in families.items() if "OWASP" in name), None)
    assert owasp is not None, f"OWASP family missing from coverage: {sorted(families)}"
    assert owasp["total_requirements"] >= 5  # ASI01/02/03/09/10 at minimum
    # A configured detector with no observation is not positive assurance.
    assert owasp["satisfied"] == 0
    assert owasp["unknown"] == owasp["total_requirements"]
    assert owasp["coverage_pct"] == 0
    org.close()


def test_unrelated_model_telemetry_does_not_satisfy_agentic_requirements(super_admin_client):
    org, headers = _org(super_admin_client, "unrelated")
    now = datetime.now(UTC).isoformat()
    assert org.post("/v1/events/batch", json={"events": [_model_call("unrelated", "s1", now)]}, headers=headers).status_code == 200
    owasp = next(entry for name, entry in _coverage(org).items() if "OWASP" in name)
    assert owasp["satisfied"] == 0
    assert owasp["unknown"] == owasp["total_requirements"]
    org.close()


def test_registered_agent_observation_is_scoped_and_expires(super_admin_client):
    org, headers = _org(super_admin_client, "observed")
    assert org.post("/api/agent-registry", json={"agent_name": "helper", "owner_ref": "a@observed.test", "autonomy_level": 1, "allowed_tools": []}).status_code == 200

    def run(span: str, timestamp: str) -> dict:
        return {
            "type": "agent.run", "schema_version": "2026-01", "trace_id": f"trc_{span}", "span_id": f"spn_{span}",
            "timestamp": timestamp, "service": "svc", "environment": "prod", "project": "p1",
            "attributes": {"agent_name": "helper", "step_count": 0, "outcome": "ok",
                           "metadata": {"tenant_id": "observed", "application_name": "helper-app", "workflow_name": "wf"}},
        }

    stale = (datetime.now(UTC) - timedelta(days=120)).isoformat()
    assert org.post("/v1/events/batch", json={"events": [run("old", stale)]}, headers=headers).status_code == 200
    ref = "OWASP Agentic ASI10"
    assert ref in next(entry for entry in _coverage(org).values() if "OWASP" in entry["framework"])["unknown_requirements"]

    current = datetime.now(UTC).isoformat()
    assert org.post("/v1/events/batch", json={"events": [run("new", current)]}, headers=headers).status_code == 200
    owasp = next(entry for entry in _coverage(org).values() if "OWASP" in entry["framework"])
    assert ref in owasp["satisfied_requirements"]
    scoped = org.get("/api/compliance/framework-coverage", params={"project": "p2"}).json()["framework_coverage"]
    assert ref in next(entry for entry in scoped if "OWASP" in entry["framework"])["unknown_requirements"]
    org.close()


def test_open_finding_marks_its_requirement_as_a_gap(super_admin_client):
    org, headers = _org(super_admin_client, "beta")
    now = datetime.now(UTC).isoformat()
    assert org.post("/v1/events/batch", json={"events": [_model_call("beta", "s1", now)]}, headers=headers).status_code == 200

    # the provider-dependency rule (NIST AI RMF MAP 3.2) now has an open finding
    risks = org.get("/api/risk-register").json()["risks"]
    assert any(r["rule_id"] == "RISK-TPD-001" and r["status"] == "open" for r in risks)

    families = _coverage(org)
    nist = families.get("NIST AI RMF")
    assert nist is not None
    assert "NIST AI RMF MAP 3.2" in nist["gaps"], "an open violation must show as a gap"
    org.close()


def test_retired_system_telemetry_is_a_finding(super_admin_client):
    org, headers = _org(super_admin_client, "gamma")
    early = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    assert org.post("/v1/events/batch", json={"events": [_model_call("gamma", "s1", early)]}, headers=headers).status_code == 200

    gov = _gov_user(org, "gamma")
    intake = gov.post(
        "/api/intake",
        json={
            "application_name": "gamma-app",
            "use_case": "claims triage",
            "description": "d",
            "intended_purpose": "p",
            "data_sensitivity": "internal",
            "autonomy_level": "assistive",
            "project": "p1",
            "environment": "prod",
        },
    )
    assert intake.status_code == 200, intake.text
    intake_id = intake.json()["intake"]["intake_id"]
    retired = gov.post(f"/api/intake/{intake_id}/retire", json={"rationale": "decommissioned"})
    assert retired.status_code == 200, retired.text

    # no post-retirement telemetry yet: retiring alone is not a violation
    risks = org.get("/api/risk-register").json()["risks"]
    assert not any(r["rule_id"] == "RISK-LCY-001" for r in risks)

    late = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    assert org.post("/v1/events/batch", json={"events": [_model_call("gamma", "s2", late)]}, headers=headers).status_code == 200

    risks = org.get("/api/risk-register").json()["risks"]
    finding = next((r for r in risks if r["rule_id"] == "RISK-LCY-001"), None)
    assert finding is not None, "telemetry after retirement produced no finding"
    assert finding["status"] == "open"
    assert finding["application_name"] == "gamma-app"
    org.close()
    gov.close()


def test_packet_reports_tenant_audit_count_not_platform_total(super_admin_client):
    org_a, _ = _org(super_admin_client, "delta")
    org_b, _ = _org(super_admin_client, "epsilon")
    # give epsilon extra audit activity delta must not be able to measure
    for _ in range(5):
        org_b.get("/api/events")

    packet = org_a.get("/api/compliance/audit-packet").json()
    trail = packet["audit_trail"]
    assert trail["integrity"]["ok"] is True
    assert trail["integrity"]["chain_ok"] is True
    assert trail["integrity"]["completeness_ok"] is None
    assert "entries" not in trail["integrity"], "global chain length leaked into a tenant packet"
    from app.storage.audit import count_audit_logs

    assert trail["tenant_entries"] == count_audit_logs(tenant_id="delta")
    assert all(entry["tenant_id"] == "delta" for entry in trail["recent_entries"])
    org_a.close()
    org_b.close()


def _sdk_health(tenant: str, span: str, **attributes) -> dict:
    return {
        "type": "sdk.health",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "name": "initialized",
        "status": "success",
        "attributes": {
            "mode": "observe",
            "fail_open": True,
            "failed_sends": 0,
            "dropped": 0,
            **attributes,
            "metadata": {"tenant_id": tenant, "application_name": f"{tenant}-app"},
        },
    }


def test_sdk_without_a_spool_is_an_evidence_finding(super_admin_client):
    """a batch the SDK drops is a gap in the audit record; the platform cannot
    see the dropped events, but it can see the SDK admit it may drop them"""
    org, headers = _org(super_admin_client, "delta")

    # a spooling SDK is not a finding
    ok = _sdk_health("delta", "h1", spool_configured=True, durable=False)
    assert org.post("/v1/events/batch", json={"events": [ok]}, headers=headers).status_code == 200
    risks = org.get("/api/risk-register").json()["risks"]
    assert not any(r["rule_id"] == "RISK-EVD-001" for r in risks)

    # an older SDK that cannot say either way is not a finding until it drops
    legacy = _sdk_health("delta", "h2")
    assert org.post("/v1/events/batch", json={"events": [legacy]}, headers=headers).status_code == 200
    risks = org.get("/api/risk-register").json()["risks"]
    assert not any(r["rule_id"] == "RISK-EVD-001" for r in risks)

    # no spool: finding
    bare = _sdk_health("delta", "h3", spool_configured=False, durable=False)
    assert org.post("/v1/events/batch", json={"events": [bare]}, headers=headers).status_code == 200
    risks = org.get("/api/risk-register").json()["risks"]
    finding = next((r for r in risks if r["rule_id"] == "RISK-EVD-001"), None)
    assert finding is not None, "an SDK with no spool produced no finding"
    assert finding["status"] == "open"
    assert finding["severity"] == "High"
    assert finding["application_name"] == "delta-app"
    assert "no spool" in finding["evidence_summary"]
    org.close()


def test_sdk_that_dropped_events_is_an_evidence_finding(super_admin_client):
    org, headers = _org(super_admin_client, "eps")
    dropped = _sdk_health("eps", "h1", dropped=7)
    assert org.post("/v1/events/batch", json={"events": [dropped]}, headers=headers).status_code == 200
    risks = org.get("/api/risk-register").json()["risks"]
    finding = next((r for r in risks if r["rule_id"] == "RISK-EVD-001"), None)
    assert finding is not None, "an SDK reporting dropped events produced no finding"
    assert "7 event(s) dropped" in finding["evidence_summary"]
    org.close()

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
    # nothing observed yet, so every monitored requirement is clean
    assert owasp["satisfied"] == owasp["total_requirements"]
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
    assert trail["integrity"] == {"ok": True}
    assert "entries" not in trail["integrity"], "global chain length leaked into a tenant packet"
    from app.storage.audit import count_audit_logs

    assert trail["tenant_entries"] == count_audit_logs(tenant_id="delta")
    assert all(entry["tenant_id"] == "delta" for entry in trail["recent_entries"])
    org_a.close()
    org_b.close()

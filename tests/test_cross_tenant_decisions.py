"""one organization cannot act on another organization's records by id

the mutation endpoints load their target by primary key, so isolation depends on
the authorization check comparing the target's tenant with the actor's. these
drive the real endpoints with a valid id belonging to someone else
"""

from __future__ import annotations

from tests.helpers import login_and_activate

FORBIDDEN = {401, 403, 404}


def _event(tenant_id: str, span: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": span,
        "timestamp": "2026-08-22T00:00:02Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {
            "provider": "openai", "model": "gpt-4o",
            "usage": {"input_tokens": 5, "output_tokens": 5},
            "metadata": {"tenant_id": tenant_id, "application_name": "PayApp", "workflow_name": "wf"},
        },
    }


def _org_with_findings(super_admin_client, tenant_id: str, email: str, password: str):
    """an organization with telemetry, a governance_admin, and open findings"""
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": tenant_id, "name": tenant_id.title(), "admin_email": email,
              "admin_display_name": "OA", "admin_password": password},
    )
    with TestClient(app) as org:
        login_and_activate(org, email, password)
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        gov_email = f"gov@{tenant_id}.test"
        org.post("/api/org/users",
                 json={"email": gov_email, "display_name": "Gov", "password": f"{tenant_id}-gov-pw-1"})
        org.post("/api/org/role-assignments",
                 json={"user_ref": gov_email, "role": "governance_admin"})
        sent = org.post("/v1/events/batch", json={"events": [
            _event(tenant_id, f"{tenant_id}_call"),
            {"type": "deployment.event", "schema_version": "2026-01", "trace_id": f"trc_{tenant_id}",
             "span_id": f"{tenant_id}_dep", "timestamp": "2026-08-22T00:00:03Z", "service": "svc",
             "environment": "prod", "project": "p1", "status": "success",
             "attributes": {"deployment_id": "dep-1", "version": "v1", "artifact_ref": "img:1",
                            "provider": "openai", "model": "gpt-4o", "prompt_version": "v1",
                            "deployment_status": "pending",
                            "metadata": {"tenant_id": tenant_id, "application_name": "PayApp",
                                         "workflow_name": "wf"}}},
        ]}, headers={"Authorization": f"Bearer {token}"})
        assert sent.status_code == 200, sent.text
    return gov_email, f"{tenant_id}-gov-pw-1"


def _victim_ids(tenant_id: str) -> dict[str, str]:
    from app.storage.raw_events import connect

    with connect() as connection:
        finding = connection.execute(
            "SELECT finding_id FROM risk_findings WHERE tenant_id = ? LIMIT 1", (tenant_id,)
        ).fetchone()
        gate = connection.execute(
            "SELECT gate_id FROM deployment_approval_gates WHERE tenant_id = ? LIMIT 1", (tenant_id,)
        ).fetchone()
    assert finding is not None and gate is not None, "victim fixture produced no records"
    return {"finding_id": finding["finding_id"], "gate_id": gate["gate_id"]}


def test_one_org_cannot_decide_on_another_orgs_records(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    _org_with_findings(super_admin_client, "victim", "oa@victim.test", "victim-pw-111")
    attacker_email, attacker_password = _org_with_findings(
        super_admin_client, "attacker", "oa@attacker.test", "attacker-pw-11"
    )
    victim = _victim_ids("victim")

    with TestClient(app) as attacker:
        login_and_activate(attacker, attacker_email, attacker_password)

        # accepting someone else's risk finding would clear their gate blocker
        decided = attacker.post("/api/decisions", json={
            "target_type": "risk_finding", "target_id": victim["finding_id"],
            "decision": "accept_risk", "rationale": "accepting a finding that belongs to another organization",
        })
        assert decided.status_code in FORBIDDEN, decided.text

        # approving someone else's release
        approved = attacker.post(f"/api/deployment-gates/{victim['gate_id']}/approve",
                                 json={"rationale": "approving a release that belongs to another organization"})
        assert approved.status_code in FORBIDDEN, approved.text

        # waiving someone else's finding via an exception
        excepted = attacker.post("/api/exceptions", json={
            "target_type": "risk_finding", "target_id": victim["finding_id"],
            "reason": "waiving a finding that belongs to another organization",
            "compensating_control": "none, this should not be accepted",
            "expires_at": "2099-12-31",
        })
        assert excepted.status_code in FORBIDDEN, excepted.text

    # the victim's records are untouched
    from app.storage.raw_events import connect

    with connect() as connection:
        finding = connection.execute(
            "SELECT status FROM risk_findings WHERE finding_id = ?", (victim["finding_id"],)
        ).fetchone()
        gate = connection.execute(
            "SELECT gate_status FROM deployment_approval_gates WHERE gate_id = ?", (victim["gate_id"],)
        ).fetchone()
        exceptions = connection.execute(
            "SELECT COUNT(*) AS n FROM governance_exceptions WHERE target_id = ?", (victim["finding_id"],)
        ).fetchone()
    assert finding["status"] in {"open", "mitigation_required"}
    assert gate["gate_status"] == "pending_review"
    assert int(exceptions["n"]) == 0


def test_one_org_cannot_read_or_set_another_orgs_retention(super_admin_client):
    from app.main import app
    from app.storage.retention import retention_days_for
    from fastapi.testclient import TestClient

    _org_with_findings(super_admin_client, "victim", "oa@victim.test", "victim-pw-111")
    attacker_email, attacker_password = _org_with_findings(
        super_admin_client, "attacker", "oa@attacker.test", "attacker-pw-11"
    )

    with TestClient(app) as attacker:
        login_and_activate(attacker, attacker_email, attacker_password)
        # the endpoint is scoped to the caller's own organization, never a named one
        configured = attacker.post("/api/retention-policy", json={"retention_days": 7})
        assert configured.status_code == 200, configured.text
        assert attacker.get("/api/retention-policy").json()["tenant_id"] == "attacker"

    assert retention_days_for("attacker") == 7
    assert retention_days_for("victim") is None

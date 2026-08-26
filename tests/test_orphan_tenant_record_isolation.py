"""a record with no tenant of its own cannot be reached through the tenant API

tenant isolation on decision/owner/exception endpoints rests on the loaded
record's tenant matching the actor's. A record whose tenant_id is NULL must not
be adoptable: borrowing the acting tenant would let any org decide on an
orphaned record. This proves such a record is refused, not adopted.
"""

from __future__ import annotations

from tests.helpers import login_and_activate

META = {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"}


def _model_call(span: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": "trc_o",
        "span_id": span,
        "timestamp": "2026-08-22T00:00:02Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {"provider": "openai", "model": "gpt-4o",
                       "usage": {"input_tokens": 10, "output_tokens": 5}, "metadata": META},
    }


def test_a_tenantless_record_cannot_be_decided_by_a_tenant_actor(super_admin_client):
    from app.main import app
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={
        "tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
        "admin_display_name": "OA", "admin_password": "oa-password-1"})
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        org.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
        org.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
        assert org.post("/v1/events/batch", json={"events": [_model_call("s1")]},
                        headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # take a real finding and orphan it: strip its tenant
    with connect() as connection:
        row = connection.execute("SELECT finding_id FROM risk_findings LIMIT 1").fetchone()
        assert row is not None, "expected the model call to produce a risk finding"
        finding_id = row["finding_id"]
        connection.execute("UPDATE risk_findings SET tenant_id = NULL WHERE finding_id = ?", (finding_id,))

    # a governance_admin (who holds risk.accept) still cannot decide it: the
    # record has no tenant, so the scope check refuses rather than adopting the
    # acting tenant
    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        resp = gov.post("/api/decisions", json={
            "target_type": "risk_finding", "target_id": finding_id, "decision": "accept_risk",
            "rationale": "attempting to decide a record that carries no tenant of its own",
        })
        assert resp.status_code == 403, resp.text

    # and the record is unchanged
    with connect() as connection:
        status = connection.execute(
            "SELECT status FROM risk_findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()["status"]
    assert status == "open", status

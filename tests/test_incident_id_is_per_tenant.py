"""an incident id is unique only within its organization

the reporting client chooses incident_id, so two organizations can both have
INC-A. closing one must load, update and record the decision for the caller's
own record and leave the other organization's record untouched, whichever row
the database happens to return first
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import login_and_activate

INCIDENT_ID = "INC-A"


def _incident_event(tenant_id: str) -> dict:
    return {
        "type": "incident.event",
        "schema_version": "2026-01",
        "trace_id": f"trc_{tenant_id}",
        "span_id": f"spn_{tenant_id}",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "error",
        "attributes": {
            "incident_id": INCIDENT_ID,
            "title": f"{tenant_id} incident",
            "severity": "High",
            "incident_status": "open",
            "metadata": {"tenant_id": tenant_id, "application_name": "PayApp", "workflow_name": "wf"},
        },
    }


def _org_with_incident(super_admin_client, tenant_id: str) -> tuple[str, str]:
    """an organization that reported INC-A, and its governance admin's login"""
    from app.main import app

    admin_email, admin_password = f"oa@{tenant_id}.test", f"{tenant_id}-oa-pw-1"
    created = super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant_id,
            "name": tenant_id.title(),
            "admin_email": admin_email,
            "admin_display_name": "OA",
            "admin_password": admin_password,
        },
    )
    assert created.status_code == 200, created.text
    gov_email, gov_password = f"gov@{tenant_id}.test", f"{tenant_id}-gov-pw-1"
    with TestClient(app) as org:
        login_and_activate(org, admin_email, admin_password)
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        assert (
            org.post(
                "/api/org/users", json={"email": gov_email, "display_name": "Gov", "password": gov_password}
            ).status_code
            == 200
        )
        assert (
            org.post("/api/org/role-assignments", json={"user_ref": gov_email, "role": "governance_admin"}).status_code
            == 200
        )
        sent = org.post(
            "/v1/events/batch",
            json={"events": [_incident_event(tenant_id)]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert sent.status_code == 200, sent.text
    return gov_email, gov_password


def _incident_rows() -> dict[str, dict]:
    from app.storage.raw_events import connect

    with connect() as connection:
        rows = connection.execute(
            "SELECT tenant_id, status, actor_ref, resolution_rationale FROM governance_incidents WHERE incident_id = ?",
            (INCIDENT_ID,),
        ).fetchall()
    return {row["tenant_id"]: dict(row) for row in rows}


def test_closing_an_incident_touches_only_the_callers_organization(super_admin_client):
    from app.main import app

    # beta reports first so that, in insertion order, beta's row is the one an
    # unbound lookup by id would return
    _org_with_incident(super_admin_client, "beta")
    acme_gov, acme_password = _org_with_incident(super_admin_client, "acme")
    assert set(_incident_rows()) == {"acme", "beta"}

    with TestClient(app) as acme:
        login_and_activate(acme, acme_gov, acme_password)
        closed = acme.post(f"/api/incidents/{INCIDENT_ID}/close", json={"rationale": "resolved by acme"})
        assert closed.status_code == 200, closed.text
        assert closed.json()["incident"]["tenant_id"] == "acme"
        assert closed.json()["decision"]["tenant_id"] == "acme"

    rows = _incident_rows()
    assert rows["acme"]["status"] == "closed"
    assert rows["acme"]["actor_ref"] == acme_gov
    assert rows["beta"]["status"] == "open"
    assert rows["beta"]["actor_ref"] is None
    assert rows["beta"]["resolution_rationale"] is None


def test_each_organization_sees_only_its_own_incident_and_owner(super_admin_client):
    from app.main import app

    beta_gov, beta_password = _org_with_incident(super_admin_client, "beta")
    acme_gov, acme_password = _org_with_incident(super_admin_client, "acme")

    with TestClient(app) as acme:
        login_and_activate(acme, acme_gov, acme_password)
        listed = acme.get("/api/incidents").json()["incidents"]
        assert [row["tenant_id"] for row in listed] == ["acme"]
        detail = acme.get(f"/api/incidents/{INCIDENT_ID}").json()
        assert detail["incident"]["tenant_id"] == "acme"
        # an owner assigned on acme's incident is not an owner of beta's
        for owner in detail["owners"]:
            assert owner["tenant_id"] == "acme"

    with TestClient(app) as beta:
        login_and_activate(beta, beta_gov, beta_password)
        assert [row["tenant_id"] for row in beta.get("/api/incidents").json()["incidents"]] == ["beta"]
        # beta's closing after acme's is still beta's own record
        closed = beta.post(f"/api/incidents/{INCIDENT_ID}/close", json={"rationale": "resolved by beta"})
        assert closed.status_code == 200, closed.text
    rows = _incident_rows()
    assert rows["beta"]["status"] == "closed" and rows["beta"]["actor_ref"] == beta_gov
    assert rows["acme"]["status"] == "open"


def test_the_platform_operator_cannot_close_a_tenant_incident(super_admin_client):
    _org_with_incident(super_admin_client, "acme")
    closed = super_admin_client.post(
        f"/api/incidents/{INCIDENT_ID}/close", json={"rationale": "closed by the platform operator"}
    )
    assert closed.status_code in {403, 404}, closed.text
    assert _incident_rows()["acme"]["status"] == "open"

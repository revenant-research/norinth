"""each organization sets its own telemetry retention window

the window is opt-in, applies only to the organization that set it, and deletes
raw events only; derived governance records and the audit log are kept
"""

from __future__ import annotations

from tests.helpers import login_and_activate


def _event(tenant_id: str, span: str, timestamp: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": span,
        "timestamp": timestamp,
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


def _org(super_admin_client, tenant_id: str, email: str, password: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": tenant_id, "name": tenant_id.title(), "admin_email": email,
              "admin_display_name": "OA", "admin_password": password},
    )
    client = TestClient(app)
    login_and_activate(client, email, password)
    token = client.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
    return client, token


def _count_events(tenant_id: str) -> int:
    from app.storage.raw_events import connect

    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS n FROM sdk_events WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
    return int(row["n"])


def test_retention_window_is_per_organization(super_admin_client):
    from app.services import maintenance

    keeper, keeper_token = _org(super_admin_client, "keeper", "oa@keeper.test", "keeper-pw-11")
    ager, ager_token = _org(super_admin_client, "ager", "oa@ager.test", "ager-pw-1111")

    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as anon:
        for tenant, token in (("keeper", keeper_token), ("ager", ager_token)):
            resp = anon.post("/v1/events/batch", json={"events": [
                _event(tenant, f"{tenant}_old", "2020-01-01T00:00:00Z"),
                _event(tenant, f"{tenant}_new", "2026-08-24T00:00:00Z"),
            ]}, headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200, resp.text

    assert _count_events("keeper") == 2
    assert _count_events("ager") == 2

    # only one organization opts into ageing its telemetry out
    configured = ager.post("/api/retention-policy", json={"retention_days": 30})
    assert configured.status_code == 200, configured.text
    assert configured.json()["retention_policy"]["retention_days"] == 30

    result = maintenance.run_once()
    assert result["purged_events"].get("ager") == 1, result

    # the organization that set a window aged out its old event, the other is untouched
    assert _count_events("ager") == 1
    assert _count_events("keeper") == 2

    keeper.close()
    ager.close()


def test_a_window_shorter_than_the_floor_is_rejected(super_admin_client):
    org, _ = _org(super_admin_client, "acme", "oa@acme.test", "acme-pw-111")
    rejected = org.post("/api/retention-policy", json={"retention_days": 1})
    assert rejected.status_code == 400, rejected.text
    assert "at least" in rejected.json()["detail"]
    assert org.get("/api/retention-policy").json()["retention_days"] is None
    org.close()


def test_no_window_means_nothing_is_deleted(super_admin_client):
    from app.services import maintenance

    org, token = _org(super_admin_client, "acme", "oa@acme.test", "acme-pw-111")
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as anon:
        anon.post("/v1/events/batch", json={"events": [_event("acme", "old", "2020-01-01T00:00:00Z")]},
                  headers={"Authorization": f"Bearer {token}"})

    assert org.get("/api/retention-policy").json()["retention_days"] is None
    assert maintenance.run_once()["purged_events"] == {}
    assert _count_events("acme") == 1
    org.close()


def test_purge_is_recorded_in_the_audit_log(super_admin_client):
    from app.services import maintenance
    from app.storage.audit import list_audit_logs

    org, token = _org(super_admin_client, "acme", "oa@acme.test", "acme-pw-111")
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as anon:
        anon.post("/v1/events/batch", json={"events": [_event("acme", "old", "2020-01-01T00:00:00Z")]},
                  headers={"Authorization": f"Bearer {token}"})
    org.post("/api/retention-policy", json={"retention_days": 30})
    maintenance.run_once()

    actions = [row["action"] for row in list_audit_logs(tenant_id="acme")]
    assert "retention.purge_events" in actions
    assert "retention.configure" in actions
    org.close()

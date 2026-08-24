"""retention and right-to-erasure"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _provision_and_ingest(super_admin_client, tid, email):
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tid,
            "name": tid,
            "admin_email": email,
            "admin_display_name": f"{tid} admin",
            "admin_password": f"{tid}-admin-pw-1",
        },
    )
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as org:
        login_and_activate(org, email, f"{tid}-admin-pw-1")
        token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
        org.post(
            "/v1/events/batch",
            json={
                "events": [
                    {
                        "type": "model.call",
                        "schema_version": "2026-01",
                        "trace_id": f"trc_{tid}",
                        "span_id": f"spn_{tid}",
                        "timestamp": "2026-08-22T00:00:00Z",
                        "service": "svc",
                        "environment": "prod",
                        "project": "p1",
                        "attributes": {
                            "provider": "openai",
                            "model": "gpt-4o",
                            "operation": "chat",
                            "usage": {"input_tokens": 1, "output_tokens": 1},
                            "metadata": {"tenant_id": tid, "application_name": f"{tid}-app", "workflow_name": "wf"},
                        },
                    }
                ]
            },
            headers={"Authorization": f"Bearer {token}"},
        )


def test_purge_requires_matching_confirmation(super_admin_client):
    _provision_and_ingest(super_admin_client, "acme", "a@acme.test")
    bad = super_admin_client.post(
        "/api/admin/organizations/acme/purge", json={"confirm_tenant_id": "wrong"}
    )
    assert bad.status_code == 400


def test_purge_erases_tenant_and_isolates_others(super_admin_client):
    _provision_and_ingest(super_admin_client, "acme", "a@acme.test")
    _provision_and_ingest(super_admin_client, "beta", "a@beta.test")

    preview = super_admin_client.get("/api/admin/organizations/acme/data")
    assert preview.status_code == 200
    assert preview.json()["total_rows"] > 0

    purged = super_admin_client.post(
        "/api/admin/organizations/acme/purge", json={"confirm_tenant_id": "acme"}
    )
    assert purged.status_code == 200, purged.text
    assert purged.json()["purged"] is True

    from app.storage.raw_events import connect

    with connect() as connection:
        acme_events = connection.execute(
            "SELECT COUNT(*) AS n FROM sdk_events WHERE tenant_id = 'acme'"
        ).fetchone()["n"]
        beta_events = connection.execute(
            "SELECT COUNT(*) AS n FROM sdk_events WHERE tenant_id = 'beta'"
        ).fetchone()["n"]
        acme_org = connection.execute(
            "SELECT COUNT(*) AS n FROM organizations WHERE tenant_id = 'acme'"
        ).fetchone()["n"]
        acme_users = connection.execute(
            "SELECT COUNT(*) AS n FROM platform_users WHERE tenant_id = 'acme'"
        ).fetchone()["n"]

    assert acme_events == 0  # acme's telemetry erased
    assert acme_org == 0  # organization removed
    assert acme_users == 0  # accounts removed
    assert beta_events == 1  # beta untouched


def test_purge_preserves_the_audit_chain(super_admin_client):
    _provision_and_ingest(super_admin_client, "acme", "a@acme.test")
    super_admin_client.post(
        "/api/admin/organizations/acme/purge", json={"confirm_tenant_id": "acme"}
    )
    # tamper-evident audit log is retained, so its chain still verifies
    verify = super_admin_client.get("/api/admin/audit-logs/verify")
    assert verify.status_code == 200
    assert verify.json()["ok"] is True


def test_retention_purges_old_events(super_admin_client):
    # event dated well in the past so a 1-day retention window ages it out
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO sdk_events
                (event_type, schema_version, trace_id, span_id, timestamp, service, environment,
                 project, status, raw_event)
            VALUES ('model.call', '2026-01', 'old', 'old', '2020-01-01T00:00:00Z', 'svc', 'prod',
                    'p1', 'success', '{}')
            """
        )

    resp = super_admin_client.post(
        "/api/admin/retention/purge-events", json={"retention_days": 1}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] >= 1


def test_purge_requires_super_admin(super_admin_client):
    # activation rotates the password, so don't re-login with the original
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "acme",
            "admin_email": "a@acme.test",
            "admin_display_name": "A",
            "admin_password": "acme-admin-pw-1",
        },
    )
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as org:
        login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
        resp = org.post("/api/admin/organizations/acme/purge", json={"confirm_tenant_id": "acme"})
        assert resp.status_code == 403

"""/api/scopes must not reveal another tenant's project or environment names

project and environment strings are tenant data: a project named after a
confidential initiative leaks its existence to every other tenant if the
scope listing is built from an unfiltered DISTINCT over all events.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc"}


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


def _event(tenant: str, project: str, environment: str) -> dict:
    return {
        **BASE,
        "type": "model.call",
        "trace_id": f"t_{tenant}",
        "span_id": f"s_{tenant}",
        "timestamp": "2026-08-22T00:00:01Z",
        "project": project,
        "environment": environment,
        "attributes": {
            "provider": "openai",
            "model": "gpt-4o",
            "operation": "chat",
            "metadata": {"tenant_id": tenant, "application_name": "app", "workflow_name": "wf"},
        },
    }


def test_scopes_listing_is_tenant_scoped(super_admin_client):
    acme, ah = _org(super_admin_client, "acme")
    beta, bh = _org(super_admin_client, "beta")

    assert (
        acme.post(
            "/v1/events/batch",
            json={"events": [_event("acme", "acme-public-app", "prod")]},
            headers=ah,
        ).status_code
        == 200
    )
    assert (
        beta.post(
            "/v1/events/batch",
            json={"events": [_event("beta", "CONFIDENTIAL-oncology-triage", "beta-staging")]},
            headers=bh,
        ).status_code
        == 200
    )

    acme_scopes = acme.get("/api/scopes").json()
    assert acme_scopes["tenants"] == ["acme"]
    assert "acme-public-app" in acme_scopes["projects"]
    # the leak: beta's confidential project/environment named in acme's listing
    assert "CONFIDENTIAL-oncology-triage" not in acme_scopes["projects"]
    assert "beta-staging" not in acme_scopes["environments"]

    beta_scopes = beta.get("/api/scopes").json()
    assert beta_scopes["projects"] == ["CONFIDENTIAL-oncology-triage"]
    assert "acme-public-app" not in beta_scopes["projects"]
    acme.close()
    beta.close()


def test_scopes_listing_empty_for_super_admin(super_admin_client):
    listing = super_admin_client.get("/api/scopes").json()
    assert listing == {"tenants": [], "projects": [], "environments": []}

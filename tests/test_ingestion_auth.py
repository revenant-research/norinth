"""Regression tests for ingestion authentication and tenant binding (audit C-1).

Before this fix, ingestion was guarded by a single hard-coded ``Bearer dev``
token and the tenant was taken from the client-supplied event payload, so anyone
who could reach the endpoint could forge governance evidence for any tenant.
Now the tenant is derived from a per-tenant key and enforced on every event.
"""

from __future__ import annotations


def _model_call_event(tenant_id: str | None) -> dict:
    metadata: dict = {"application_name": "App", "workflow_name": "wf"}
    if tenant_id is not None:
        metadata["tenant_id"] = tenant_id
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": "trc_x",
        "span_id": "spn_x",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "provider": "openai",
            "model": "gpt-4o",
            "operation": "chat",
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "metadata": metadata,
        },
    }


def _ingest(client, token: str | None, event: dict):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.post("/v1/events/batch", json={"events": [event]}, headers=headers)


def test_ingestion_requires_a_key(client):
    assert _ingest(client, None, _model_call_event("tenant-local")).status_code == 401


def test_ingestion_rejects_invalid_key(client):
    assert _ingest(client, "not-a-real-key", _model_call_event("tenant-local")).status_code == 401


def test_dev_key_accepts_its_own_tenant(client):
    resp = _ingest(client, "dev", _model_call_event("tenant-local"))
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1


def test_dev_key_cannot_forge_another_tenant(client):
    # The dev key is bound to tenant-local; claiming another tenant must fail.
    resp = _ingest(client, "dev", _model_call_event("victim-corp"))
    assert resp.status_code == 403, resp.text


def test_ingestion_stamps_authenticated_tenant_when_omitted(client):
    resp = _ingest(client, "dev", _model_call_event(None))
    assert resp.status_code == 200, resp.text

    # The stored event must carry the key's tenant, never NULL.
    from app.storage.raw_events import connect

    with connect() as connection:
        rows = connection.execute(
            "SELECT DISTINCT tenant_id FROM sdk_events WHERE event_type = 'model.call'"
        ).fetchall()
    tenants = {row["tenant_id"] for row in rows}
    assert tenants == {"tenant-local"}


def test_ingestion_key_lifecycle(super_admin_client):
    # Provision an org with an admin.
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "beta",
            "name": "Beta",
            "admin_email": "admin@beta.test",
            "admin_display_name": "Beta Admin",
            "admin_password": "beta-admin-pw-1",
        },
    )

    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as org:
        org.post(
            "/api/auth/login",
            json={"email": "admin@beta.test", "password": "beta-admin-pw-1"},
        )
        created = org.post("/api/ingestion-keys", json={"name": "prod app"})
        assert created.status_code == 200, created.text
        body = created.json()
        token = body["token"]
        key_id = body["ingestion_key"]["key_id"]
        assert token.startswith("nrk_")
        assert "key_hash" not in body["ingestion_key"]  # secret never leaves storage

        # The new key ingests for the beta tenant...
        ok = _ingest(org, token, _model_call_event("beta"))
        assert ok.status_code == 200, ok.text
        # ...but cannot forge tenant-local.
        assert _ingest(org, token, _model_call_event("tenant-local")).status_code == 403

        # Revoke, then the key is rejected.
        revoked = org.post(f"/api/ingestion-keys/{key_id}/revoke")
        assert revoked.status_code == 200, revoked.text
        assert _ingest(org, token, _model_call_event("beta")).status_code == 401


def test_org_admin_cannot_manage_another_tenants_keys(super_admin_client):
    # Create two orgs; beta admin must not see gamma's keys (list is tenant-scoped).
    for tid, email in [("beta", "a@beta.test"), ("gamma", "a@gamma.test")]:
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

    with TestClient(app) as gamma:
        gamma.post("/api/auth/login", json={"email": "a@gamma.test", "password": "gamma-admin-pw-1"})
        gamma.post("/api/ingestion-keys", json={"name": "gamma key"})

    with TestClient(app) as beta:
        beta.post("/api/auth/login", json={"email": "a@beta.test", "password": "beta-admin-pw-1"})
        listing = beta.get("/api/ingestion-keys")
        assert listing.status_code == 200
        # beta sees only its own (zero) keys, not gamma's.
        assert listing.json()["ingestion_keys"] == []

"""a retried batch must not inflate governance metrics

sdk_events dedups a retry by (tenant, trace, span), but the derived projections
increment (model_calls += 1, tokens += ...). Replaying the same batch must
project each event exactly once, or a client retry doubles the inventory metrics
and token totals.
"""

from __future__ import annotations

from tests.helpers import login_and_activate

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}


def _model_call() -> dict:
    return {
        "type": "model.call", "schema_version": "2026-01", "trace_id": "trc_r", "span_id": "spn_r",
        "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
        "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 10, "output_tokens": 4}, "metadata": META},
    }


def test_replaying_a_batch_does_not_double_count(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={
        "tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
        "admin_display_name": "OA", "admin_password": "oa-password-1"})
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    first = org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h)
    assert first.status_code == 200 and first.json()["accepted"] == 1

    # exact same batch again (a client retry): dedup keeps one raw row, and the
    # retry reports nothing accepted
    retry = org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h)
    assert retry.status_code == 200 and retry.json()["accepted"] == 0

    from app.storage.raw_events import connect

    with connect() as connection:
        raw = connection.execute(
            "SELECT COUNT(*) AS n FROM sdk_events WHERE tenant_id = 'acme'"
        ).fetchone()["n"]
    assert raw == 1  # dedup held at the raw layer

    app_row = org.get("/api/applications").json()["applications"][0]
    # the projection counted the call once, not twice
    assert int(app_row["model_calls"]) == 1, app_row
    assert int(app_row["input_tokens"]) == 10, app_row
    assert int(app_row["output_tokens"]) == 4, app_row

    org.close()

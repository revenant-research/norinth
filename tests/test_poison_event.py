"""object-typed attribute given as a string is rejected at ingestion and never poisons recompute"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}
META = {"tenant_id": "acme", "application_name": "A", "workflow_name": "w"}


def _good(span: str) -> dict:
    return {**BASE, "type": "model.call", "trace_id": f"t{span}", "span_id": f"s{span}", "timestamp": "2026-08-22T00:00:00Z",
            "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 1, "output_tokens": 1}, "metadata": META}}


def test_poison_event_is_rejected_and_ingestion_keeps_working(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": "acme", "name": "Acme", "admin_email": "a@acme.test", "admin_display_name": "A", "admin_password": "acme-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    h = {"Authorization": f"Bearer {org.post('/api/ingestion-keys', json={'name': 'k'}).json()['token']}"}

    assert org.post("/v1/events/batch", json={"events": [_good("1")]}, headers=h).status_code == 200

    # prompt as a string
    poison = {**BASE, "type": "model.call", "trace_id": "tp", "span_id": "sp", "timestamp": "2026-08-22T00:00:00Z",
              "attributes": {"provider": "openai", "model": "gpt-4o", "prompt": "Summarize this chart", "metadata": META}}
    r = org.post("/v1/events/batch", json={"events": [poison]}, headers=h)
    assert r.status_code == 422 and "prompt must be an object" in r.text

    # other object-typed attrs are also rejected
    for key in ("metadata", "usage", "template", "attestation"):
        attrs = {"provider": "openai", "model": "gpt-4o", "metadata": dict(META)}
        attrs[key] = "not-an-object"
        bad = {**BASE, "type": "model.call", "trace_id": f"t_{key}", "span_id": f"s_{key}", "timestamp": "2026-08-22T00:00:00Z", "attributes": attrs}
        assert org.post("/v1/events/batch", json={"events": [bad]}, headers=h).status_code in (400, 422), key

    # ingestion still works for everyone afterwards
    assert org.post("/v1/events/batch", json={"events": [_good("2")]}, headers=h).status_code == 200
    assert org.get("/api/summary").status_code == 200
    org.close()


def test_stored_poison_row_does_not_crash_recompute(fresh_db):
    """bad row written directly to storage (bypassing ingestion check) survives recompute"""
    import json

    from app.storage.governance_policy import refresh_governance_assessments
    from app.storage.raw_events import connect

    poison = {"type": "model.call", "trace_id": "t", "span_id": "s", "timestamp": "2026-08-22T00:00:00Z",
              "service": "svc", "environment": "prod", "project": "p1",
              "attributes": {"provider": "openai", "model": "gpt-4o", "prompt": "a string", "metadata": {"tenant_id": "acme", "application_name": "A", "workflow_name": "w"}}}
    with connect() as connection:
        connection.execute("INSERT INTO governance_applications (entity_id, tenant_id, project, environment, application_name, use_cases, model_purposes, providers, models, model_calls, errors, first_seen, last_seen) VALUES ('e', 'acme', 'p1', 'prod', 'A', '[]', '[]', '[]', '[]', 1, 0, 'x', 'x')")
        connection.execute("INSERT INTO sdk_events (event_type, schema_version, trace_id, span_id, timestamp, service, environment, project, status, tenant_id, application_name, workflow_name, raw_event) VALUES ('model.call', '2026-01', 't', 's', 'x', 'svc', 'prod', 'p1', 'success', 'acme', 'A', 'w', ?)", (json.dumps(poison),))
    # must not raise
    refresh_governance_assessments([{"tenant_id": "acme", "project": "p1", "environment": "prod", "application_name": "A"}])

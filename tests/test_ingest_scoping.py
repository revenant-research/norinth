"""ingest recomputes derived state only for scopes the batch touched"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}


def _events(tenant: str, suffix: str) -> list[dict]:
    meta = {"tenant_id": tenant, "application_name": f"{tenant}-app", "workflow_name": "wf"}
    return [
        {**BASE, "type": "deployment.event", "trace_id": f"td_{tenant}_{suffix}", "span_id": f"sd_{tenant}_{suffix}", "timestamp": "2026-08-22T00:00:02Z",
         "attributes": {"deployment_id": f"dep-{tenant}", "version": "v1", "artifact_ref": "img:1", "prompt_version": "p1", "deployment_status": "pending", "metadata": meta}},
        {**BASE, "type": "model.call", "trace_id": f"tm_{tenant}_{suffix}", "span_id": f"sm_{tenant}_{suffix}", "timestamp": "2026-08-22T00:00:03Z",
         "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 1, "output_tokens": 1}, "metadata": meta}},
    ]


def test_batch_scopes_extraction():
    from app.ingestion.routes import batch_scopes

    scopes = batch_scopes(_events("acme", "x") + _events("acme", "y"))
    assert scopes == [{"tenant_id": "acme", "project": "p1", "environment": "prod", "application_name": "acme-app"}]
    assert batch_scopes([{**BASE, "type": "model.call", "attributes": {}}]) == []


def test_ingest_recomputes_only_touched_scopes(super_admin_client):
    from app.main import app
    from app.storage.deployments import refresh_deployment_gates
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    clients, headers = {}, {}
    for tenant in ("acme", "beta"):
        super_admin_client.post("/api/admin/organizations", json={"tenant_id": tenant, "name": tenant, "admin_email": f"oa@{tenant}.test", "admin_display_name": "A", "admin_password": "oa-password-1"})
        org = TestClient(app)
        login_and_activate(org, f"oa@{tenant}.test", "oa-password-1")
        clients[tenant] = org
        headers[tenant] = {"Authorization": f"Bearer {org.post('/api/ingestion-keys', json={'name': 'k'}).json()['token']}"}
        assert org.post("/v1/events/batch", json={"events": _events(tenant, "seed")}, headers=headers[tenant]).status_code == 200

    assert len(clients["beta"].get("/api/deployment-gates").json()["deployment_gates"]) == 1

    # drop beta's gate row; if ingest recomputed globally acme's batch would recreate it
    with connect() as connection:
        connection.execute("DELETE FROM deployment_approval_gates WHERE tenant_id = 'beta'")
    assert clients["acme"].post("/v1/events/batch", json={"events": _events("acme", "second")}, headers=headers["acme"]).status_code == 200
    assert clients["acme"].get("/api/deployment-gates").json()["deployment_gates"], "acme's own gate is maintained"
    assert clients["beta"].get("/api/deployment-gates").json()["deployment_gates"] == [], "beta was not recomputed by acme's ingest"

    # beta's own ingest restores it
    assert clients["beta"].post("/v1/events/batch", json={"events": _events("beta", "second")}, headers=headers["beta"]).status_code == 200
    assert len(clients["beta"].get("/api/deployment-gates").json()["deployment_gates"]) == 1

    # no-argument form recomputes everything
    with connect() as connection:
        connection.execute("DELETE FROM deployment_approval_gates")
    refresh_deployment_gates()
    assert len(clients["acme"].get("/api/deployment-gates").json()["deployment_gates"]) == 1
    assert len(clients["beta"].get("/api/deployment-gates").json()["deployment_gates"]) == 1
    for org in clients.values():
        org.close()

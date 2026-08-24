"""maker-checker on release gates: the deployer of a version cannot approve its gate"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}
META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}


def test_deployer_cannot_approve_own_release(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": "acme", "name": "Acme", "admin_email": "a@acme.test", "admin_display_name": "A", "admin_password": "acme-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    # two governance admins
    for email in ("gov1@acme.test", "gov2@acme.test"):
        org.post("/api/org/users", json={"email": email, "display_name": email, "password": "gov-password-1"})
        org.post("/api/org/role-assignments", json={"user_ref": email, "role": "governance_admin"})
    h = {"Authorization": f"Bearer {org.post('/api/ingestion-keys', json={'name': 'k'}).json()['token']}"}

    # gov1 deployed this version; its gate names gov1 as deployed_by
    events = [
        {**BASE, "type": "prompt.event", "trace_id": "tp", "span_id": "sp", "timestamp": "2026-08-22T00:00:01Z", "attributes": {"prompt_id": "p", "version": "v1", "artifact_ref": "pr:1", "metadata": META}},
        {**BASE, "type": "deployment.event", "trace_id": "td", "span_id": "sd", "timestamp": "2026-08-22T00:00:02Z", "attributes": {"deployment_id": "dep-1", "version": "v1", "artifact_ref": "img:1", "prompt_version": "v1", "deployment_status": "pending", "deployed_by": "gov1@acme.test", "metadata": META}},
        {**BASE, "type": "eval.result", "trace_id": "te", "span_id": "se", "timestamp": "2026-08-22T00:00:03Z", "status": "success", "attributes": {"eval_id": "s", "passed": True, "score": 0.9, "artifact_ref": "img:1", "prompt_version": "v1", "metadata": META}},
    ]
    org.post("/v1/events/batch", json={"events": events}, headers=h)
    gate = org.get("/api/deployment-gates").json()["deployment_gates"][0]
    gid = gate["gate_id"]

    with TestClient(app) as g1:
        login_and_activate(g1, "gov1@acme.test", "gov-password-1")
        r = g1.post(f"/api/deployment-gates/{gid}/approve", json={"rationale": "mine, approving my own deploy"})
        assert r.status_code == 403 and "originated" in r.text.lower()
    # a different governance admin may approve when no open risks/controls
    fresh = {g["gate_id"]: g for g in org.get("/api/deployment-gates").json()["deployment_gates"]}[gid]
    if fresh["risk_count"] == 0 and fresh["missing_control_count"] == 0:
        with TestClient(app) as g2:
            login_and_activate(g2, "gov2@acme.test", "gov-password-1")
            ok = g2.post(f"/api/deployment-gates/{gid}/approve", json={"rationale": "reviewed gov1's release, evidence bound"})
            assert ok.status_code == 200, ok.text
    org.close()

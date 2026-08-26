"""a decided release gate cannot be silently re-decided

once a human approves or rejects this version's gate, the verdict is final:
a second admin must not be able to flip an approval to a rejection, or re-approve
a rejected release, with no distinct action. new telemetry already preserves a
decided status; a superseding build gets its own gate.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}
META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}


def _approvable_gate(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={
        "tenant_id": "acme", "name": "Acme", "admin_email": "a@acme.test",
        "admin_display_name": "A", "admin_password": "acme-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    # deployer (gov1) and an independent approver (gov2), so maker-checker allows gov2
    for email in ("gov1@acme.test", "gov2@acme.test"):
        org.post("/api/org/users", json={"email": email, "display_name": email, "password": "gov-password-1"})
        org.post("/api/org/role-assignments", json={"user_ref": email, "role": "governance_admin"})
    h = {"Authorization": f"Bearer {org.post('/api/ingestion-keys', json={'name': 'k'}).json()['token']}"}
    events = [
        {**BASE, "type": "prompt.event", "trace_id": "tp", "span_id": "sp", "timestamp": "2026-08-22T00:00:01Z",
         "attributes": {"prompt_id": "p", "version": "v1", "artifact_ref": "pr:1", "metadata": META}},
        {**BASE, "type": "deployment.event", "trace_id": "td", "span_id": "sd", "timestamp": "2026-08-22T00:00:02Z",
         "attributes": {"deployment_id": "dep-1", "version": "v1", "artifact_ref": "img:1", "prompt_version": "v1",
                        "deployment_status": "pending", "deployed_by": "gov1@acme.test", "metadata": META}},
        {**BASE, "type": "eval.result", "trace_id": "te", "span_id": "se", "timestamp": "2026-08-22T00:00:03Z",
         "status": "success", "attributes": {"eval_id": "s", "passed": True, "score": 0.9, "artifact_ref": "img:1",
                                             "prompt_version": "v1", "metadata": META}},
    ]
    org.post("/v1/events/batch", json={"events": events}, headers=h)
    gid = org.get("/api/deployment-gates").json()["deployment_gates"][0]["gate_id"]
    org.close()
    return gid


def test_an_approved_gate_cannot_be_rejected_or_re_approved(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    gid = _approvable_gate(super_admin_client)

    with TestClient(app) as gov2:
        login_and_activate(gov2, "gov2@acme.test", "gov-password-1")
        approved = gov2.post(f"/api/deployment-gates/{gid}/approve",
                             json={"rationale": "reviewed the release, evidence bound, approving"})
        assert approved.status_code == 200, approved.text
        assert approved.json()["deployment_gate"]["gate_status"] == "approved"

        # the verdict is final: it cannot be flipped to rejected...
        flipped = gov2.post(f"/api/deployment-gates/{gid}/reject",
                            json={"rationale": "changed my mind and rejecting the already-approved gate"})
        assert flipped.status_code == 400, flipped.text
        assert "already been approved" in flipped.json()["detail"].lower()

        # ...nor re-approved
        again = gov2.post(f"/api/deployment-gates/{gid}/approve",
                          json={"rationale": "approving the already-approved gate a second time"})
        assert again.status_code == 400, again.text

        # and the stored status is still the original approval
        gate = gov2.get(f"/api/deployment-gates/{gid}").json()
        gate = gate.get("deployment_gate", gate)
        assert gate["gate_status"] == "approved"

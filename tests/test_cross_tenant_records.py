"""One tenant's ingestion key cannot overwrite or re-tenant another tenant's
deployment, incident, prompt or eval records (critical C2), and colliding
human ids across tenants do not collide in storage.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}


def _org(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": tenant, "name": tenant, "admin_email": f"a@{tenant}.test", "admin_display_name": "A", "admin_password": f"{tenant}-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, {"Authorization": f"Bearer {token}"}


def _meta(tenant: str) -> dict:
    return {"tenant_id": tenant, "application_name": "shared-name-app", "workflow_name": "wf"}


def test_cross_tenant_record_overwrite_is_impossible(super_admin_client):
    acme, ah = _org(super_admin_client, "acme")
    beta, bh = _org(super_admin_client, "beta")

    # Same human ids in both tenants: deployment "prod-api", prompt "triage", incident "INC-1", eval on the same trace/span.
    def batch(tenant: str, deploy_ver: str, artifact: str, prompt_ver: str, eval_passed: bool) -> list[dict]:
        m = _meta(tenant)
        return [
            {**BASE, "type": "deployment.event", "trace_id": "t_dep", "span_id": "s_dep", "timestamp": "2026-08-22T00:00:01Z",
             "attributes": {"deployment_id": "prod-api", "version": deploy_ver, "artifact_ref": artifact, "prompt_version": prompt_ver, "deployment_status": "pending", "metadata": m}},
            {**BASE, "type": "prompt.event", "trace_id": "t_pr", "span_id": "s_pr", "timestamp": "2026-08-22T00:00:01Z",
             "attributes": {"prompt_id": "triage", "version": prompt_ver, "artifact_ref": "pr:" + prompt_ver, "template": {"x": tenant}, "metadata": m}},
            {**BASE, "type": "incident.event", "trace_id": "t_in", "span_id": "s_in", "timestamp": "2026-08-22T00:00:01Z", "name": "n",
             "attributes": {"incident_id": "INC-1", "title": f"{tenant} incident", "severity": "high", "metadata": m}},
            {**BASE, "type": "eval.result", "trace_id": "t_ev", "span_id": "s_ev", "timestamp": "2026-08-22T00:00:01Z", "status": "success",
             "attributes": {"eval_id": "safety", "passed": eval_passed, "score": 0.9, "metadata": m}},
        ]

    assert acme.post("/v1/events/batch", json={"events": batch("acme", "1.0.0", "sha256:acme-good", "pv-acme", True)}, headers=ah).status_code == 200
    # Beta sends the same ids with hostile values.
    assert beta.post("/v1/events/batch", json={"events": batch("beta", "9.9.9", "sha256:beta-evil", "pv-beta", False)}, headers=bh).status_code == 200

    # acme's records are untouched.
    dep = acme.get("/api/deployments").json()["deployments"]
    assert len(dep) == 1 and dep[0]["current_version"] == "1.0.0" and dep[0]["artifact_ref"] == "sha256:acme-good"
    inc = {i["title"] for i in acme.get("/api/incidents").json()["incidents"]}
    assert inc == {"acme incident"}
    # evals: acme's passing eval still passing and attributed to acme.
    evals = [e for e in acme.get("/api/evals").json()["evals"]]
    assert evals and all(e["passed"] for e in evals)

    # beta sees only its own hostile values, in its own tenant.
    bdep = beta.get("/api/deployments").json()["deployments"]
    assert len(bdep) == 1 and bdep[0]["current_version"] == "9.9.9"
    binc = {i["title"] for i in beta.get("/api/incidents").json()["incidents"]}
    assert binc == {"beta incident"}

    # Each tenant has exactly one eval row (no cross-tenant dedup collision on t_ev/s_ev).
    assert len(acme.get("/api/evals").json()["evals"]) == 1
    assert len(beta.get("/api/evals").json()["evals"]) == 1
    acme.close()
    beta.close()

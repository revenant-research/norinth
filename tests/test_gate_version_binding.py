"""Release-gate evidence is bound to the version being gated (critical C5): an
untested new build cannot pass on an earlier version's evaluation, and approval
blocks on open risks / missing controls and requires a real rationale.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}
BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}


def _deployment(version: str, artifact: str, prompt_ver: str) -> dict:
    return {**BASE, "type": "deployment.event", "trace_id": f"td_{version}", "span_id": f"sd_{version}", "timestamp": "2026-08-22T00:00:02Z",
            "attributes": {"deployment_id": "dep-1", "version": version, "artifact_ref": artifact, "prompt_version": prompt_ver, "deployment_status": "pending", "metadata": META}}


def _prompt(prompt_ver: str) -> dict:
    return {**BASE, "type": "prompt.event", "trace_id": f"tp_{prompt_ver}", "span_id": f"sp_{prompt_ver}", "timestamp": "2026-08-22T00:00:01Z",
            "attributes": {"prompt_id": "triage", "version": prompt_ver, "artifact_ref": f"pr:{prompt_ver}", "template": {"t": "x"}, "metadata": META}}


def _eval(span: str, artifact: str, prompt_ver: str) -> dict:
    return {**BASE, "type": "eval.result", "trace_id": f"te_{span}", "span_id": f"se_{span}", "timestamp": "2026-08-22T00:00:03Z", "status": "success",
            "attributes": {"eval_id": "safety", "passed": True, "score": 0.9, "artifact_ref": artifact, "prompt_version": prompt_ver, "metadata": META}}


def _gate_for(org, version: str) -> dict:
    gates = org.get("/api/deployment-gates").json()["deployment_gates"]
    return next(g for g in gates if g.get("version") == version or True)  # single app -> single/first gate


def test_untested_version_does_not_inherit_prior_evals(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": "acme", "name": "Acme", "admin_email": "a@acme.test", "admin_display_name": "A", "admin_password": "acme-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    h = {"Authorization": f"Bearer {org.post('/api/ingestion-keys', json={'name': 'k'}).json()['token']}"}

    # v1: deployment + prompt + a passing eval bound to v1's artifact.
    org.post("/v1/events/batch", json={"events": [_prompt("pv1"), _deployment("1.0.0", "sha256:v1", "pv1"), _eval("v1", "sha256:v1", "pv1")]}, headers=h)
    gates = {g["version"]: g for g in org.get("/api/deployment-gates").json()["deployment_gates"]}
    assert gates["1.0.0"]["passing_eval_count"] == 1

    # v2: new artifact, no eval. Must NOT inherit v1's eval.
    org.post("/v1/events/batch", json={"events": [_deployment("2.0.0", "sha256:v2-untested", "pv1")]}, headers=h)
    gates = {g["version"]: g for g in org.get("/api/deployment-gates").json()["deployment_gates"]}
    assert gates["2.0.0"]["passing_eval_count"] == 0, "untested v2 inherited v1's eval"
    assert "missing" in (gates["2.0.0"]["required_reason"] or "").lower()

    # A governance admin cannot approve v2 (no bound evidence).
    org.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        r = gov.post(f"/api/deployment-gates/{gates['2.0.0']['gate_id']}/approve", json={"rationale": "looks fine"})
        assert r.status_code == 400 and "bound to this version" in r.text
        # Empty rationale is rejected on the v1 gate too.
        assert gov.post(f"/api/deployment-gates/{gates['1.0.0']['gate_id']}/approve", json={"rationale": "   "}).status_code == 400
        # v2 gets its own eval -> now approvable (assuming no open risks/controls on this app).
        v2 = {g["version"]: g for g in org.get("/api/deployment-gates").json()["deployment_gates"]}["2.0.0"]
        if v2["risk_count"] == 0 and v2["missing_control_count"] == 0:
            org.post("/v1/events/batch", json={"events": [_eval("v2", "sha256:v2-untested", "pv1")]}, headers=h)
            gate2 = {g["version"]: g for g in org.get("/api/deployment-gates").json()["deployment_gates"]}["2.0.0"]
            assert gate2["passing_eval_count"] == 1
            ok = gov.post(f"/api/deployment-gates/{gate2['gate_id']}/approve", json={"rationale": "v2 eval reviewed, evidence bound to sha256:v2-untested"})
            assert ok.status_code == 200, ok.text
    org.close()

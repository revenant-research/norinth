"""/v1/gates/check endpoint and the norinth gate check cli around it"""

from __future__ import annotations

import io
import pathlib
import sys
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}
BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}


def _deployment(version: str) -> dict:
    return {**BASE, "type": "deployment.event", "trace_id": f"trc_{version}", "span_id": f"spn_{version}", "timestamp": "2026-08-22T00:00:02Z",
            "attributes": {"deployment_id": "dep-1", "version": version, "artifact_ref": f"img:{version}", "provider": "openai", "model": "gpt-4o",
                           "prompt_version": "p1", "deployment_status": "pending", "metadata": META}}


def _prompt() -> dict:
    return {**BASE, "type": "prompt.event", "trace_id": "trc_prompt", "span_id": "spn_prompt", "timestamp": "2026-08-22T00:00:01Z",
            "attributes": {"prompt_id": "p", "version": "p1", "artifact_ref": "prompt:p1", "template": {"t": "x"}, "metadata": META}}


def _eval() -> dict:
    return {**BASE, "type": "eval.result", "trace_id": "trc_eval", "span_id": "spn_eval", "timestamp": "2026-08-22T00:00:03Z", "status": "success",
            "attributes": {"eval_id": "safety", "passed": True, "score": 0.9, "prompt_version": "p1", "artifact_ref": "img:v1", "metadata": META}}


def _org(super_admin_client, tenant: str, email: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": tenant, "name": tenant, "admin_email": email, "admin_display_name": "A", "admin_password": "oa-password-1"})
    client = TestClient(app)
    login_and_activate(client, email, "oa-password-1")
    token = client.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
    return client, token


def test_gate_check_is_tenant_bound_and_reflects_human_approval(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    acme, acme_key = _org(super_admin_client, "acme", "oa@acme.test")
    _, beta_key = _org(super_admin_client, "beta", "oa@beta.test")
    anon = TestClient(app)

    assert anon.get("/v1/gates/check", params={"deployment_id": "dep-1", "version": "v1"}).status_code == 401
    h = {"Authorization": f"Bearer {acme_key}"}
    assert acme.get("/v1/gates/check", params={"deployment_id": "dep-1", "version": "v1"}, headers=h).status_code == 404

    assert acme.post("/v1/events/batch", json={"events": [_prompt(), _deployment("v1"), _eval()]}, headers=h).status_code == 200
    pending = acme.get("/v1/gates/check", params={"deployment_id": "dep-1", "version": "v1"}, headers=h).json()
    assert pending["approved"] is False and pending["status"] == "pending_review"

    # another org's key cannot see acme's gate
    assert acme.get("/v1/gates/check", params={"deployment_id": "dep-1", "version": "v1"}, headers={"Authorization": f"Bearer {beta_key}"}).status_code == 404

    # governance admin (not the org admin) approves; ci then sees approved + who decided
    acme.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
    acme.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        resp = gov.post(f"/api/deployment-gates/{pending['gate_id']}/approve", json={"rationale": "evidence reviewed"})
        assert resp.status_code == 200, resp.text
    approved = acme.get("/v1/gates/check", params={"deployment_id": "dep-1", "version": "v1"}, headers=h).json()
    assert approved["approved"] is True and approved["decided_by"] == "gov@acme.test" and approved["blocking"] is None
    acme.close()


def test_cli_gate_check_and_doctor_exit_codes(super_admin_client, monkeypatch):
    """drive the cli against the in-process app by routing its http through testclient"""
    from app.main import app
    from fastapi.testclient import TestClient
    from norinth_logger import cli

    acme, key = _org(super_admin_client, "acme", "oa@acme.test")
    h = {"Authorization": f"Bearer {key}"}
    acme.post("/v1/events/batch", json={"events": [_prompt(), _deployment("v1")]}, headers=h)
    tc = TestClient(app)

    def fake_http(method, url, *, key=None, body=None, timeout=10.0):
        path = url.split("http://norinth.test", 1)[1]
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        resp = tc.request(method, path, json=body, headers=headers)
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, resp.text

    monkeypatch.setattr(cli, "_http", fake_http)
    monkeypatch.setenv("NORINTH_ENDPOINT", "http://norinth.test")
    monkeypatch.setenv("NORINTH_API_KEY", key)

    out = io.StringIO()
    with redirect_stdout(out):
        assert cli.main(["gate", "check", "--deployment", "dep-1", "--version", "v1"]) == 1  # pending
        assert cli.main(["gate", "check", "--deployment", "dep-1", "--version", "v404"]) == 2  # unknown
        assert cli.main(["doctor"]) == 0
    assert "pending_review" in out.getvalue() and "ingestion key accepted" in out.getvalue()

    monkeypatch.setenv("NORINTH_API_KEY", "nrk_wrong")
    out = io.StringIO()
    with redirect_stdout(out):
        assert cli.main(["doctor"]) == 1
        assert cli.main(["gate", "check", "--deployment", "dep-1", "--version", "v1"]) == 3
    assert "rejected (401)" in out.getvalue()
    acme.close()


def test_cli_init_writes_env_and_scan_compat(tmp_path, monkeypatch):
    from norinth_logger import cli

    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli.main(["init", "--endpoint", "https://n.example/", "--api-key", "nrk_x", "--project", "p", "--environment", "prod", "--service", "s"])
    assert rc == 0
    env = (tmp_path / ".env").read_text()
    assert "NORINTH_ENDPOINT=https://n.example\n" in env and "NORINTH_API_KEY=nrk_x" in env
    assert "openai" in out.getvalue().lower()
    # re-running keeps other lines and replaces NORINTH_* ones
    (tmp_path / ".env").write_text("OTHER=1\n" + env)
    with redirect_stdout(io.StringIO()):
        cli.main(["init", "--endpoint", "https://n2.example", "--api-key", "nrk_y", "--project", "p", "--environment", "prod", "--service", "s"])
    env2 = (tmp_path / ".env").read_text()
    assert env2.startswith("OTHER=1\n") and env2.count("NORINTH_API_KEY=") == 1 and "nrk_y" in env2
    # legacy positional form still runs the scanner
    with redirect_stdout(io.StringIO()):
        assert cli.main([str(tmp_path), "-o", str(tmp_path / "m.json")]) == 0
    assert (tmp_path / "m.json").exists()

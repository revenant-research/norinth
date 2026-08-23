"""Tests for the agentic-governance module: agent registry + runtime posture."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, token


def _agent_run(agent: str, trace: str, tools: list[str]) -> list[dict]:
    base = {
        "schema_version": "2026-01",
        "trace_id": trace,
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
    }
    meta = {"tenant_id": "acme", "application_name": "claims-app", "workflow_name": "wf"}
    events = [
        {
            **base,
            "type": "agent.run",
            "span_id": f"spn_{trace}_run",
            "attributes": {"agent_name": agent, "steps": [{"tool": t} for t in tools], "step_count": len(tools), "outcome": "ok", "metadata": meta},
        }
    ]
    for index, tool in enumerate(tools):
        events.append(
            {
                **base,
                "type": "tool.call",
                "span_id": f"spn_{trace}_tool{index}",
                "attributes": {"tool_name": tool, "metadata": meta},
            }
        )
    return events


def _ingest(org, token, events):
    resp = org.post("/v1/events/batch", json={"events": events}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text


def test_shadow_agent_is_detected_and_registered_agent_is_clean(super_admin_client):
    org, token = _org(super_admin_client)

    # Register one agent with a tool allow-list; a second agent is never registered.
    reg = org.post(
        "/api/agent-registry",
        json={
            "agent_name": "claims-triage",
            "owner_ref": "oa@acme.test",
            "autonomy_level": 2,
            "allowed_tools": ["lookup_claim", "summarize"],
            "processes_untrusted_input": True,
            "accesses_sensitive_data": True,
            "can_act_externally": False,
            "human_checkpoint": True,
        },
    )
    assert reg.status_code == 200, reg.text
    assert reg.json()["agent"]["autonomy_level_label"].startswith("supervised")

    _ingest(org, token, _agent_run("claims-triage", "t1", ["lookup_claim", "summarize"]))
    _ingest(org, token, _agent_run("rogue-bot", "t2", ["send_email"]))

    posture = org.get("/api/agents/posture").json()
    by_name = {a["agent_name"]: a for a in posture["agents"]}
    assert by_name["claims-triage"]["registered"] is True
    assert by_name["claims-triage"]["issues"] == []
    assert by_name["rogue-bot"]["registered"] is False
    assert "unregistered_agent" in by_name["rogue-bot"]["issues"]
    assert posture["summary"]["shadow"] == 1

    # The shadow agent produced a risk finding mapped to OWASP Agentic ASI10.
    risks = org.get("/api/risk-register").json()["risks"]
    shadow = [r for r in risks if r.get("rule_id", "").startswith("RISK-AGT-SHADOW")]
    assert shadow, risks
    assert any("OWASP Agentic ASI10" in ref for ref in shadow[0]["framework_refs"])
    org.close()


def test_unauthorized_tool_use_is_flagged(super_admin_client):
    org, token = _org(super_admin_client)
    org.post(
        "/api/agent-registry",
        json={"agent_name": "helper", "owner_ref": "oa@acme.test", "autonomy_level": 1, "allowed_tools": ["search"]},
    )
    _ingest(org, token, _agent_run("helper", "t3", ["search", "delete_records"]))

    posture = org.get("/api/agents/posture").json()
    helper = next(a for a in posture["agents"] if a["agent_name"] == "helper")
    assert "unauthorized_tool" in helper["issues"]
    assert helper["unauthorized_tools"] == ["delete_records"]
    risks = org.get("/api/risk-register").json()["risks"]
    assert any(r.get("rule_id", "").startswith("RISK-AGT-TOOL") for r in risks)
    org.close()


def test_lethal_trifecta_and_autonomy_without_oversight(super_admin_client):
    org, token = _org(super_admin_client)
    org.post(
        "/api/agent-registry",
        json={
            "agent_name": "autopilot",
            "owner_ref": "oa@acme.test",
            "autonomy_level": 4,
            "allowed_tools": ["browse", "send_email"],
            "processes_untrusted_input": True,
            "accesses_sensitive_data": True,
            "can_act_externally": True,
            "human_checkpoint": False,
        },
    )
    _ingest(org, token, _agent_run("autopilot", "t4", ["browse"]))

    posture = org.get("/api/agents/posture").json()
    auto = next(a for a in posture["agents"] if a["agent_name"] == "autopilot")
    assert "agent_trifecta" in auto["issues"]
    assert "autonomy_without_oversight" in auto["issues"]
    risks = org.get("/api/risk-register").json()["risks"]
    trifecta = [r for r in risks if r.get("rule_id", "").startswith("RISK-AGT-TRIFECTA")]
    assert trifecta and trifecta[0]["severity"] == "Critical"
    org.close()


def test_registry_requires_config_write_and_is_tenant_scoped(super_admin_client):
    org, _token = _org(super_admin_client)
    # Super admin (no tenant) cannot register.
    resp = super_admin_client.post(
        "/api/agent-registry", json={"agent_name": "x", "owner_ref": "o", "autonomy_level": 1}
    )
    assert resp.status_code == 403
    # Retire works for the org, 404 for unknown.
    created = org.post("/api/agent-registry", json={"agent_name": "tmp", "owner_ref": "o", "autonomy_level": 1}).json()["agent"]
    assert org.post(f"/api/agent-registry/{created['agent_id']}/retire").status_code == 200
    assert org.post("/api/agent-registry/nope/retire").status_code == 404
    org.close()


def test_agent_posture_appears_in_audit_packet_and_owasp_coverage(super_admin_client):
    org, token = _org(super_admin_client)
    _ingest(org, token, _agent_run("ghost", "t5", ["x"]))
    packet = org.get("/api/compliance/audit-packet").json()
    assert "agent_registry" in packet and "agent_posture" in packet
    assert packet["agent_posture"]["summary"]["shadow"] == 1
    org.close()

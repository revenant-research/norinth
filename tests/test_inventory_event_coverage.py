# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""the inventory covers every runtime event type, not just model.call

upsert_application ran only for model.call, so an application whose model calls
went through an unwrapped path reported agent.run and tool.call and never
entered the inventory. these tests pin the record to the application name rather
than the event type, and keep model_calls counting only model calls
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {
    "schema_version": "2026-01",
    "timestamp": "2026-08-22T00:00:00Z",
    "service": "svc",
    "environment": "prod",
    "project": "p1",
}


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


def _meta(application: str, **extra):
    return {"tenant_id": "acme", "application_name": application, **extra}


def _event(event_type: str, span: str, attributes: dict) -> dict:
    return {**BASE, "type": event_type, "trace_id": f"trc_{span}", "span_id": f"spn_{span}", "attributes": attributes}


def _ingest(org, token, events):
    resp = org.post("/v1/events/batch", json={"events": events}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    return resp


def _applications(org) -> dict[str, dict]:
    return {a["application_name"]: a for a in org.get("/api/applications").json()["applications"]}


def test_agentic_application_without_a_model_call_is_in_the_inventory(super_admin_client):
    org, token = _org(super_admin_client)
    _ingest(
        org,
        token,
        [
            _event("agent.run", "a1", {"agent_name": "triage", "step_count": 1, "outcome": "completed",
                                       "steps": [{"tool": "patient_lookup"}],
                                       "metadata": _meta("ShadowAgentApp", workflow_name="triage")}),
            _event("tool.call", "t1", {"tool_name": "patient_lookup", "status": "success",
                                       "metadata": _meta("ShadowAgentApp", workflow_name="triage")}),
        ],
    )

    applications = _applications(org)
    assert "ShadowAgentApp" in applications, applications
    assert applications["ShadowAgentApp"]["model_calls"] == 0

    workflows = {w["workflow_name"] for w in org.get("/api/workflows").json()["workflows"]}
    assert "triage" in workflows
    org.close()


RUNTIME_EVENTS = [
    ("retrieval.call", {"retriever": "kb", "document_count": 1}),
    ("tool.call", {"tool_name": "lookup", "status": "success"}),
    ("guardrail.decision", {"guardrail_name": "pii", "decision": "allow"}),
    ("agent.run", {"agent_name": "a", "step_count": 0, "outcome": "ok", "steps": []}),
    ("trace.completed", {}),
    ("sdk.health", {"mode": "observe", "fail_open": True, "failed_sends": 0}),
]


def test_every_runtime_event_type_creates_the_application(super_admin_client):
    org, token = _org(super_admin_client)
    for index, (event_type, attributes) in enumerate(RUNTIME_EVENTS):
        name = f"app-{event_type.replace('.', '-')}"
        _ingest(org, token, [_event(event_type, f"s{index}", {**attributes, "metadata": _meta(name)})])

    applications = _applications(org)
    for event_type, _ in RUNTIME_EVENTS:
        name = f"app-{event_type.replace('.', '-')}"
        assert name in applications, f"{event_type} did not create an application: {sorted(applications)}"
        assert applications[name]["model_calls"] == 0
    org.close()


def test_ci_metadata_alone_does_not_create_an_application(super_admin_client):
    """prompt, deployment and eval events carry ci evidence, not execution

    lifecycle.application_is_registered gates control assessment on inventory
    membership, so a record built from these would give an application that
    never ran a full set of missing controls and an unapprovable release gate
    """
    org, token = _org(super_admin_client)
    meta = _meta("CiOnlyApp", workflow_name="wf")
    _ingest(
        org,
        token,
        [
            _event("prompt.event", "p1", {"prompt_id": "pr-1", "version": "v1", "artifact_ref": "sha256:a",
                                          "status": "active", "metadata": meta}),
            _event("deployment.event", "d1", {"deployment_id": "dep-1", "version": "v1",
                                              "artifact_ref": "sha256:a", "status": "active", "metadata": meta}),
            _event("eval.result", "e1", {"eval_name": "safety", "score": 0.9, "threshold": 0.5,
                                         "passed": True, "prompt_version": "v1", "metadata": meta}),
        ],
    )

    assert "CiOnlyApp" not in _applications(org)

    # one runtime event and the same application is in the inventory
    _ingest(org, token, [_event("tool.call", "t9", {"tool_name": "lookup", "status": "success", "metadata": meta})])
    assert "CiOnlyApp" in _applications(org)
    org.close()


def test_model_calls_still_counts_only_model_calls(super_admin_client):
    org, token = _org(super_admin_client)
    meta = _meta("MixedApp", workflow_name="wf")
    _ingest(
        org,
        token,
        [
            _event("model.call", "m1", {"provider": "openai", "model": "gpt-4o",
                                        "usage": {"input_tokens": 10, "output_tokens": 5}, "metadata": meta}),
            _event("model.call", "m2", {"provider": "openai", "model": "gpt-4o",
                                        "usage": {"input_tokens": 1, "output_tokens": 2}, "metadata": meta}),
            _event("tool.call", "t2", {"tool_name": "lookup", "status": "success", "metadata": meta}),
            _event("agent.run", "a2", {"agent_name": "a", "step_count": 0, "outcome": "ok",
                                       "steps": [], "metadata": meta}),
        ],
    )

    application = _applications(org)["MixedApp"]
    # two model calls among four events; tool and agent events must not inflate it
    assert application["model_calls"] == 2
    assert application["input_tokens"] == 11
    assert application["output_tokens"] == 7
    assert application["providers"] == ["openai"]

    workflow = next(w for w in org.get("/api/workflows").json()["workflows"] if w["workflow_name"] == "wf")
    assert workflow["model_calls"] == 2
    org.close()


def test_events_without_an_application_name_do_not_invent_a_workflow(super_admin_client):
    org, token = _org(super_admin_client)
    # sdk.health names a lifecycle state, not a workflow
    _ingest(org, token, [{**_event("sdk.health", "h1", {"mode": "observe", "metadata": {"tenant_id": "acme"}}),
                          "name": "initialized"}])

    workflows = {w["workflow_name"] for w in org.get("/api/workflows").json()["workflows"]}
    assert "initialized" not in workflows, workflows
    assert not _applications(org)
    org.close()

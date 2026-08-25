"""every SDK emitter produces an event the platform accepts

these are the calls a customer writes. an emitter that builds a malformed event
fails only in production, silently, because the SDK is fail-open. this runs each
public emitter's output through the real ingest endpoint and asserts acceptance,
so the SDK/platform contract is covered rather than assumed
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims Copilot", "workflow_name": "triage"}


def _sdk_client_posting_to(app, token: str):
    """a real NorinthClient whose transport posts through the app's TestClient"""
    from fastapi.testclient import TestClient
    from norinth_logger.client import NorinthClient
    from norinth_logger.config import NorinthConfig

    client = NorinthClient(NorinthConfig(api_key=token, async_transport=False, project="claims",
                                         environment="prod", service="claims-api"))
    responses: list[int] = []
    ingest = TestClient(app)

    def _send_batch(events: list[dict]) -> None:
        resp = ingest.post("/v1/events/batch", json={"events": events},
                           headers={"Authorization": f"Bearer {token}"})
        responses.append(resp.status_code)
        assert resp.status_code == 200, f"ingest rejected: {resp.status_code} {resp.text}"
        assert resp.json().get("accepted", 0) >= 1, resp.text

    client.transport.send_batch = _send_batch  # type: ignore[method-assign]
    return client, responses


def test_every_public_emitter_is_accepted_by_the_platform(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]

    client, responses = _sdk_client_posting_to(app, token)

    # every emitter the SDK and docs advertise, with valid arguments
    client.deployment(deployment_id="dep-1", version="v3", application_name="Claims Copilot",
                      workflow_name="triage", artifact_ref="sha256:abc", status="active",
                      provider="openai", model="gpt-4o", prompt_version="v3", metadata=META)
    client.prompt(prompt_id="pr-1", version="v3", template="Summarize: {x}", artifact_ref="sha256:abc",
                  status="active", application_name="Claims Copilot", workflow_name="triage", metadata=META)
    client.guardrail(guardrail_name="pii", decision="block", score=0.9, matched_rules=["ssn"], metadata=META)
    client.eval_result(eval_name="safety", score=0.97, threshold=0.6, passed=True, metadata=META)
    client.agent_run(agent_name="triage-agent", steps=[{"name": "r", "type": "retrieval"}],
                     outcome="completed", duration_ms=1200, metadata=META)
    client.retrieval(retriever="kb", query="policy", documents=[{"id": "d1"}, {"id": "d2"}], metadata=META)
    client.tool_call(tool_name="lookup", arguments={"id": "P-1"}, result="found", metadata=META)
    client.incident(incident_id="inc-9", title="t", severity="Low", status="open",
                    application_name="Claims Copilot", workflow_name="triage",
                    description="a description", metadata=META)

    # eight emitters, eight accepted batches
    assert len(responses) == 8, responses
    assert all(code == 200 for code in responses)

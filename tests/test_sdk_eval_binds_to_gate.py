"""an eval emitted via the SDK can satisfy a release gate

the gate counts eval evidence only when the eval names the build it ran against
(artifact_ref, or prompt_version as a fallback), and the attestation signature
covers those same fields. If the SDK's eval_result emitter can't set them, a
customer using the documented emitter produces evals that never bind to a gate.
This drives a real SDK client through the platform and asserts the eval counts.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims Copilot", "workflow_name": "triage"}


def _sdk_client_posting_to(app, token: str):
    from fastapi.testclient import TestClient
    from norinth_logger.client import NorinthClient
    from norinth_logger.config import NorinthConfig

    client = NorinthClient(NorinthConfig(api_key=token, async_transport=False, project="claims",
                                         environment="prod", service="claims-api"))
    ingest = TestClient(app)

    def _send_batch(events: list[dict]) -> None:
        resp = ingest.post("/v1/events/batch", json={"events": events},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text

    client.transport.send_batch = _send_batch  # type: ignore[method-assign]
    return client


def test_sdk_eval_result_binds_to_the_deployment_gate(super_admin_client):
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

        client = _sdk_client_posting_to(app, token)
        # a deployed build, its prompt, and an eval that names the same build
        client.deployment(deployment_id="dep-1", version="v3", application_name="Claims Copilot",
                          workflow_name="triage", artifact_ref="sha256:abc", status="pending",
                          provider="openai", model="gpt-4o", prompt_version="v3", metadata=META)
        client.prompt(prompt_id="pr-1", version="v3", template="Summarize: {x}", artifact_ref="sha256:abc",
                      status="active", application_name="Claims Copilot", workflow_name="triage", metadata=META)
        client.eval_result(eval_name="safety", score=0.97, threshold=0.6, passed=True,
                           prompt_version="v3", artifact_ref="sha256:abc", metadata=META)

        gates = org.get("/api/deployment-gates").json()["deployment_gates"]
        assert len(gates) == 1, gates
        gate = gates[0]
        # the SDK-emitted eval bound to this build and counts as passing evidence
        assert int(gate["passing_eval_count"]) >= 1, gate
        assert gate["prompt_evidence_status"] == "linked", gate

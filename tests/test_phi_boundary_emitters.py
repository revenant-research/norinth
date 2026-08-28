"""the content boundary holds for the structured emitter channels

capture_content=False covered prompts, responses and (since #105) metadata —
but agent_run(steps=), model_call(usage=), guardrail(matched_rules=) and the
error= kwarg passed caller data verbatim. steps is the worst of the four: the
agentic path is the product's most differentiated feature, and a step's
input/output is exactly where an agent's observations (a patient record it
retrieved) end up. these tests put synthetic PHI in each channel and assert it
never leaves the process, while the labels the platform reads still arrive.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from norinth_logger.client import NorinthClient  # noqa: E402
from norinth_logger.config import NorinthConfig  # noqa: E402

PATIENT = "Jane Q. Patient"
MRN = "MRN-4417233"
NOTE = "presented with chest pain, family history of CAD"


def _capturing_client(**config: object) -> tuple[NorinthClient, list[dict]]:
    client = NorinthClient(NorinthConfig(api_key="test", async_transport=False, **config))
    captured: list[dict] = []
    client.transport.send_batch = captured.extend  # type: ignore[method-assign]
    return client, captured


def _emit_phi_through_every_structured_channel(client: NorinthClient) -> None:
    client.agent_run(
        agent_name="triage-agent",
        steps=[
            {
                "tool": "ehr_lookup",
                "name": "fetch-record",
                "type": "tool_use",
                # nested keys are inside the value and the value is summarized
                # whole, so PHI used as a nested key is covered; top-level step
                # keys are framework schema (input/output/...) by contract
                "input": {"patient": PATIENT, MRN: "note text"},
                "output": f"{PATIENT} ({MRN}): {NOTE}",
                "observation for jane@hospital.example": "redaction patterns still apply to key names",
            }
        ],
        outcome="completed",
    )
    client.model_call(
        provider="openai",
        model="gpt-4o",
        operation="chat",
        usage={"input_tokens": 12, "output_tokens": 34, "debug_echo": f"prompt was about {PATIENT}"},
        status="error",
        error={"type": "RateLimitError", "message": f"failed while summarizing {PATIENT} ({MRN})"},
    )
    client.retrieval(
        retriever="kb",
        query="q",
        documents=[{"id": "d1"}],
        status="error",
        error={"type": "LookupError", "message": f"no chart for {MRN}"},
    )
    client.tool_call(
        tool_name="lookup",
        status="error",
        error={"type": "ValueError", "message": f"bad dob for {PATIENT}"},
    )
    client.guardrail(
        guardrail_name="phi-filter",
        decision="block",
        score=0.99,
        matched_rules=["mrn-pattern", f"matched excerpt: {PATIENT} {MRN}"],
    )


def test_structured_channels_hold_the_boundary_with_capture_off():
    client, captured = _capturing_client(capture_content=False)
    _emit_phi_through_every_structured_channel(client)

    assert captured, "no events captured"
    serialized = json.dumps(captured)
    for value in (PATIENT, MRN, NOTE):
        assert value not in serialized, f"{value!r} reached the wire"


def test_governance_labels_survive_sanitization():
    """the platform reads step tool names, token counts, rule ids and error types"""
    client, captured = _capturing_client(capture_content=False)
    _emit_phi_through_every_structured_channel(client)

    by_type = {event["type"]: event for event in captured if event["type"] != "sdk.health"}

    step = by_type["agent.run"]["attributes"]["steps"][0]
    assert step["tool"] == "ehr_lookup"
    assert step["name"] == "fetch-record"
    assert step["type"] == "tool_use"
    assert step["input"]["hash"].startswith("sha256:")
    assert by_type["agent.run"]["attributes"]["step_count"] == 1

    usage = by_type["model.call"]["attributes"]["usage"]
    assert usage["input_tokens"] == 12
    assert usage["output_tokens"] == 34
    assert isinstance(usage["debug_echo"], dict), "string usage values must be summarized"

    error = by_type["model.call"]["attributes"]["error"]
    assert error["type"] == "RateLimitError"
    assert isinstance(error["message"], dict)
    assert error["message"]["hash"].startswith("sha256:")

    rules = by_type["guardrail.decision"]["attributes"]["matched_rules"]
    assert rules[0] == "mrn-pattern"
    # the excerpt entry is not identifier-shaped, so it left as a digest
    assert rules[1].startswith("sha256:")
    assert all(isinstance(rule, str) for rule in rules)


def test_matched_rules_are_labels_even_with_capture_on():
    """rule ids are labels like incident titles: redacted and capped either way"""
    client, captured = _capturing_client(capture_content=True)
    client.guardrail(
        guardrail_name="pii",
        decision="block",
        matched_rules=["email-rule for jane@hospital.example", "x" * 500],
    )
    rules = captured[-1]["attributes"]["matched_rules"]
    assert "jane@hospital.example" not in rules[0]
    assert "[redacted-email]" in rules[0]
    assert len(rules[1]) <= 256


def test_capture_on_passes_steps_through_redacted():
    client, captured = _capturing_client(capture_content=True)
    client.agent_run(
        agent_name="a",
        steps=[{"tool": "t", "output": "contact jane@hospital.example about 123-45-6789"}],
        outcome="done",
    )
    step = captured[-1]["attributes"]["steps"][0]
    assert step["tool"] == "t"
    assert step["output"] == "contact [redacted-email] about [redacted-ssn]"


def test_phi_in_structured_channels_never_reaches_storage(super_admin_client, fresh_db):
    """proved at the database through the real ingest path, same scan as the metadata test"""
    from app.main import app
    from app.storage.db import connect, is_postgres
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]

        client = NorinthClient(NorinthConfig(api_key=token, async_transport=False, project="claims",
                                             environment="prod", service="claims-api"))
        ingest = TestClient(app)

        def _send(events: list[dict]) -> None:
            resp = ingest.post("/v1/events/batch", json={"events": events},
                               headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200, resp.text

        client.transport.send_batch = _send  # type: ignore[method-assign]
        _emit_phi_through_every_structured_channel(client)

    list_tables = (
        "SELECT table_name AS name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
        if is_postgres()
        else "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )

    def _values(row) -> tuple:
        return tuple(row.values()) if hasattr(row, "values") else tuple(row)

    with connect() as connection:
        tables = [row["name"] for row in connection.execute(list_tables).fetchall()]
        haystack = []
        for table in tables:
            for row in connection.execute(f'SELECT * FROM "{table}"').fetchall():  # noqa: S608
                haystack.append(" ".join(str(value) for value in _values(row)))
    stored = "\n".join(haystack)

    for value in (PATIENT, MRN, NOTE):
        assert value not in stored, f"{value!r} was written to storage"
    # the governance signal itself still landed
    assert "ehr_lookup" in stored
    assert "mrn-pattern" in stored

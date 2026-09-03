"""the content boundary holds for app-supplied metadata and incident narrative

capture_content=false is the setting a regulated deployment relies on, so what it
covers has to be tested rather than assumed. prompts and responses were already
summarized, but metadata rode through unredacted and incident descriptions were
captured unconditionally, which put a patient name in storage on an install that
had explicitly turned capture off. these tests pin the boundary at every emitter
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from norinth_logger.client import NorinthClient  # noqa: E402
from norinth_logger.config import NorinthConfig  # noqa: E402

# a synthetic record, the kind an app hands the sdk as "just context"
PHI = {
    "patient_name": "Jane Q. Patient",
    "mrn": "MRN-4417233",
    "dob": "1974-03-02",
    "note": "presented with chest pain, family history of CAD",
}
GOVERNANCE = {"application_name": "Claims Copilot", "workflow_name": "triage", "use_case": "prior-auth"}


def _capturing_client(**config: object) -> tuple[NorinthClient, list[dict]]:
    client = NorinthClient(NorinthConfig(api_key="test", async_transport=False, **config))
    captured: list[dict] = []
    client.transport.send_batch = captured.extend  # type: ignore[method-assign]
    return client, captured


def _emit_every_metadata_carrying_emitter(client: NorinthClient, metadata: dict) -> None:
    """every public emitter that accepts metadata; a boundary is only as good as its leakiest call"""
    client.model_call(provider="openai", model="gpt-4o", operation="chat", prompt="p", response="r",
                      metadata=metadata)
    client.retrieval(retriever="kb", query="q", documents=[{"id": "d1"}], metadata=metadata)
    client.guardrail(guardrail_name="pii", decision="allow", metadata=metadata)
    client.eval_result(eval_name="safety", score=0.9, threshold=0.5, passed=True, metadata=metadata)
    client.tool_call(tool_name="lookup", arguments={"id": "P-1"}, result="ok", metadata=metadata)
    client.agent_run(agent_name="triage", steps=[{"name": "r"}], outcome="completed", metadata=metadata)
    client.prompt(prompt_id="pr-1", version="v1", template="t", artifact_ref="sha256:a", status="active",
                  application_name="Claims Copilot", workflow_name="triage", metadata=metadata)
    client.deployment(deployment_id="dep-1", version="v1", application_name="Claims Copilot",
                      workflow_name="triage", artifact_ref="sha256:a", status="active", metadata=metadata)
    client.incident(incident_id="inc-1", title="t", severity="low", status="open",
                    application_name="Claims Copilot", workflow_name="triage",
                    description="d", metadata=metadata)


def test_metadata_phi_never_leaves_the_process_with_capture_off():
    client, captured = _capturing_client(capture_content=False)
    _emit_every_metadata_carrying_emitter(client, {**PHI, **GOVERNANCE})

    assert captured, "no events captured"
    serialized = json.dumps(captured)
    for value in PHI.values():
        assert value not in serialized, f"{value!r} reached the wire from metadata"


def test_metadata_keys_and_shape_survive_so_the_leak_is_debuggable():
    """hashing the value should not hide that the key was sent at all"""
    client, captured = _capturing_client(capture_content=False)
    client.model_call(provider="openai", model="gpt-4o", operation="chat", metadata=dict(PHI))

    metadata = captured[0]["attributes"]["metadata"]
    assert set(PHI) <= set(metadata)
    assert metadata["mrn"]["hash"].startswith("sha256:")
    assert metadata["mrn"]["type"] == "str"


def test_governance_labels_still_reach_the_platform():
    """the boundary must not blind inventory; these are the keys the platform reads"""
    client, captured = _capturing_client(capture_content=False)
    _emit_every_metadata_carrying_emitter(client, {**PHI, **GOVERNANCE, "tenant_id": "acme"})

    for event in captured:
        metadata = event["attributes"]["metadata"]
        assert metadata["application_name"] == "Claims Copilot"
        assert metadata["workflow_name"] == "triage"
        assert metadata["use_case"] == "prior-auth"
        assert metadata["tenant_id"] == "acme"


def test_an_app_can_opt_one_extra_key_back_into_the_clear():
    client, captured = _capturing_client(capture_content=False, metadata_allowlist=("region",))
    client.model_call(provider="openai", model="gpt-4o", operation="chat",
                      metadata={"region": "us-east-1", "mrn": PHI["mrn"]})

    metadata = captured[0]["attributes"]["metadata"]
    assert metadata["region"] == "us-east-1"
    assert isinstance(metadata["mrn"], dict), "opting in one key must not open the rest"


def test_capture_on_still_redacts_secret_shaped_metadata():
    client, captured = _capturing_client(capture_content=True)
    client.model_call(provider="openai", model="gpt-4o", operation="chat",
                      metadata={"contact": "jane@hospital.example", "ssn": "123-45-6789"})

    metadata = captured[0]["attributes"]["metadata"]
    assert metadata["contact"] == "[redacted-email]"
    assert metadata["ssn"] == "[redacted-ssn]"


def test_incident_description_is_not_captured_when_capture_is_off():
    narrative = "Patient Jane Q. Patient (MRN-4417233) received an incorrect dosage recommendation"
    client, captured = _capturing_client(capture_content=False)
    client.incident(incident_id="inc-1", title="Dosage error", severity="high", status="open",
                    application_name="Claims Copilot", workflow_name="triage", description=narrative)

    serialized = json.dumps(captured)
    assert "Jane Q. Patient" not in serialized
    assert "MRN-4417233" not in serialized
    description = captured[0]["attributes"]["description"]
    assert "content" not in description
    assert description["hash"].startswith("sha256:")


def test_incident_narrative_is_available_when_an_org_opts_in():
    """the governance argument for keeping the narrative is real; it just has to be a choice"""
    client, captured = _capturing_client(capture_content=False, capture_incident_details=True)
    client.incident(incident_id="inc-1", title="Dosage error", severity="high", status="open",
                    application_name="Claims Copilot", workflow_name="triage",
                    description="model recommended 10x the correct dose")

    assert captured[0]["attributes"]["description"]["content"] == "model recommended 10x the correct dose"


def test_incident_title_is_redacted_and_capped():
    client, captured = _capturing_client(capture_content=False)
    client.incident(incident_id="inc-1", title="leak of jane@hospital.example " + "x" * 500,
                    severity="high", status="open", application_name="a", workflow_name="w",
                    description="d")

    title = captured[0]["attributes"]["title"]
    assert "jane@hospital.example" not in title
    assert len(title) <= 200


# --- delivery durability ----------------------------------------------------------


def test_durable_delivery_refuses_to_start_without_a_spool(tmp_path, monkeypatch):
    import pytest
    from norinth_logger.client import NorinthClient

    # strict mode fails at boot when there is nowhere to spool: switched off,
    # content capture without a chosen directory, or no writable location
    with pytest.raises(ValueError, match="switched off"):
        NorinthClient(NorinthConfig(api_key="test", durable=True, spool_dir="off"))
    with pytest.raises(ValueError, match="content capture"):
        NorinthClient(NorinthConfig(api_key="test", durable=True, capture_content=True))
    monkeypatch.setattr("norinth_logger.spool.default_spool_candidates", lambda config: [])
    with pytest.raises(ValueError, match="no writable spool directory"):
        NorinthClient(NorinthConfig(api_key="test", durable=True))

    client = NorinthClient(NorinthConfig(api_key="test", durable=True, spool_dir=str(tmp_path)))
    assert client.transport.spool_dir == str(tmp_path)



# --- end to end -------------------------------------------------------------------


def test_phi_in_metadata_never_reaches_storage(super_admin_client, fresh_db):
    """the boundary proved where it matters: the database, through the real ingest path

    the sdk-level tests above assert what goes on the wire. this one emits through
    the platform's own endpoint and then reads every text column of every table,
    because "not in the event body" is not the same claim as "not in storage"
    """
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
        _emit_every_metadata_carrying_emitter(client, {**PHI, **GOVERNANCE, "tenant_id": "acme"})
        client.incident(incident_id="inc-2", title="Dosage error", severity="high", status="open",
                        application_name="Claims Copilot", workflow_name="triage",
                        description=f"{PHI['patient_name']} ({PHI['mrn']}) got the wrong dose")

    # the suite runs against sqlite by default and postgres in CI; the scan has to
    # hold on both, so the table list comes from whichever catalog is in play
    list_tables = (
        "SELECT table_name AS name FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
        if is_postgres()
        else "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )

    def _values(row) -> tuple:
        # postgres rows are dict-shaped, sqlite3.Row is tuple-shaped; iterating a
        # dict row yields column names, which would scan the schema and find nothing
        return tuple(row.values()) if hasattr(row, "values") else tuple(row)

    with connect() as connection:
        tables = [row["name"] for row in connection.execute(list_tables).fetchall()]
        assert tables, "no tables to scan"
        haystack = []
        for table in tables:
            # identifiers come from the database's own catalog, not from input
            for row in connection.execute(f'SELECT * FROM "{table}"').fetchall():  # noqa: S608
                haystack.append(" ".join(str(value) for value in _values(row)))
    stored = "\n".join(haystack)

    for label, value in PHI.items():
        assert value not in stored, f"{label} ({value!r}) was written to storage"
    # the governance record itself still landed
    assert "Claims Copilot" in stored
    assert "Dosage error" in stored

"""The AI-BOM is valid CycloneDX and does not silently truncate (audit H7).

Previously the export stamped bomFormat/specVersion onto a bespoke JSON shape
with no components[] and read only the last 5000 events per type. This checks
that the BOM has the CycloneDX envelope, real components and dependency edges
with no dangling refs, and that models/providers observed in telemetry appear.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

_VALID_COMPONENT_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "device",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
}


def _model_call(i: int, provider: str, model: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": f"t{i}",
        "span_id": f"s{i}",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "provider": provider,
            "model": model,
            "metadata": {"application_name": "Claims Copilot", "workflow_name": "triage"},
        },
    }


@pytest.fixture
def org_with_events(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "a@acme.test",
            "admin_display_name": "Acme admin",
            "admin_password": "acme-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    events = [_model_call(0, "openai", "gpt-4o"), _model_call(1, "anthropic", "claude-haiku-4-5")]
    resp = org.post("/v1/events/batch", json={"events": events}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    try:
        yield org
    finally:
        org.close()


def test_aibom_has_cyclonedx_envelope(org_with_events):
    bom = org_with_events.get("/api/compliance/aibom").json()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["version"] == 1
    assert bom["metadata"]["component"]["type"] == "application"


def test_aibom_components_are_valid_and_include_models(org_with_events):
    bom = org_with_events.get("/api/compliance/aibom").json()
    components = bom["components"]
    assert components, "BOM must contain components"
    for component in components:
        assert component["type"] in _VALID_COMPONENT_TYPES
        assert component.get("bom-ref")
        assert component.get("name")
    model_names = {c["name"] for c in components if c["type"] == "machine-learning-model"}
    assert {"gpt-4o", "claude-haiku-4-5"} <= model_names
    provider_names = {c["name"] for c in components if c["type"] == "platform"}
    assert {"openai", "anthropic"} <= provider_names


def test_aibom_dependencies_have_no_dangling_refs(org_with_events):
    bom = org_with_events.get("/api/compliance/aibom").json()
    refs = {c["bom-ref"] for c in bom["components"]}
    refs.add(bom["metadata"]["component"]["bom-ref"])
    for edge in bom["dependencies"]:
        assert edge["ref"] in refs
        for dep in edge["dependsOn"]:
            assert dep in refs, f"dangling dependency ref: {dep}"

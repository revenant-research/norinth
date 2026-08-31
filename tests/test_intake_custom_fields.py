"""policy-declared intake fields: typed, length-capped, tier-required, and
undeclared keys rejected (the content boundary for intake extensions)"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _intake(custom_fields=None, sensitivity="restricted"):
    return {
        "application_name": "Claims",
        "use_case": "Claims triage",
        "description": "d",
        "intended_purpose": "p",
        "data_sensitivity": sensitivity,
        "autonomy_level": "supervised",
        "affects_individuals": True,
        "project": "p1",
        "environment": "prod",
        "custom_fields": custom_fields or {},
    }


FIELDS_POLICY = {
    "schema": "governance-policy/v1",
    "intake": {
        "fields": [
            {"key": "dpia_ref", "label": "DPIA reference", "type": "string", "max_length": 40, "required_tiers": ["high"]},
            {"key": "vendor_count", "label": "Vendors involved", "type": "number"},
            {"key": "phi_reviewed", "label": "PHI exposure reviewed", "type": "boolean"},
        ]
    },
}


@pytest.fixture
def org(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    client = TestClient(app)
    login_and_activate(client, "oa@acme.test", "oa-password-1")
    draft = client.post("/api/governance-policy/draft", json={"body": FIELDS_POLICY})
    version = draft.json()["policy"]["version"]
    assert client.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200
    try:
        yield client
    finally:
        client.close()


def test_undeclared_fields_are_rejected(org):
    resp = org.post("/api/intake", json=_intake({"favorite_color": "blue"}))
    assert resp.status_code == 400
    assert "favorite_color" in resp.json()["detail"]


def test_required_field_enforced_for_its_tiers_only(org):
    # high tier without the required DPIA reference is refused
    missing = org.post("/api/intake", json=_intake())
    assert missing.status_code == 400
    assert "DPIA reference" in missing.json()["detail"]
    # a lower-tier submission does not require it (required_tiers is ["high"])
    lower = _intake(sensitivity="public")
    lower["autonomy_level"] = "assistive"
    lower["affects_individuals"] = False
    ok = org.post("/api/intake", json=lower)
    assert ok.status_code == 200, ok.text
    assert ok.json()["intake"]["risk_tier"] == "limited"


def test_types_lengths_and_storage(org):
    too_long = org.post("/api/intake", json=_intake({"dpia_ref": "x" * 41}))
    assert too_long.status_code == 400
    assert "maximum length" in too_long.json()["detail"]

    wrong_type = org.post("/api/intake", json=_intake({"dpia_ref": "DPIA-77", "vendor_count": "three"}))
    assert wrong_type.status_code == 400
    assert "number" in wrong_type.json()["detail"]

    stored = org.post(
        "/api/intake",
        json=_intake({"dpia_ref": "DPIA-77", "vendor_count": 3, "phi_reviewed": True}),
    )
    assert stored.status_code == 200, stored.text
    assert stored.json()["intake"]["custom_fields"] == {"dpia_ref": "DPIA-77", "vendor_count": 3, "phi_reviewed": True}
    listed = org.get("/api/intake").json()["intake"][0]
    assert listed["custom_fields"]["dpia_ref"] == "DPIA-77"


def test_fields_are_published_with_the_effective_policy(org):
    policy = org.get("/api/governance-policy").json()["policy"]
    keys = [field["key"] for field in policy["body"]["intake"]["fields"]]
    assert keys == ["dpia_ref", "vendor_count", "phi_reviewed"]

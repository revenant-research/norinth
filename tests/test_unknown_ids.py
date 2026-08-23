"""unknown record ids return 404, not an unhandled 500"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

_RATIONALE = "Reviewed the evidence and this is acceptable."


@pytest.fixture
def org(super_admin_client):
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
    org.post("/api/org/role-assignments", json={"user_ref": "a@acme.test", "role": "governance_admin"})
    try:
        yield org
    finally:
        org.close()


def test_unknown_gate_approve_is_404(org):
    resp = org.post("/api/deployment-gates/nope/approve", json={"rationale": _RATIONALE})
    assert resp.status_code == 404, resp.text


def test_unknown_incident_close_is_404(org):
    resp = org.post("/api/incidents/nope/close", json={"rationale": _RATIONALE})
    assert resp.status_code == 404, resp.text


def test_unknown_owner_assignment_is_404(org):
    resp = org.post("/api/owner-assignments/nope/assign", json={"owner_ref": "a@acme.test"})
    assert resp.status_code == 404, resp.text


def test_unknown_decision_target_is_404(org):
    resp = org.post(
        "/api/decisions",
        json={"target_type": "review_task", "target_id": "nope", "decision": "approve", "rationale": _RATIONALE},
    )
    assert resp.status_code == 404, resp.text


def test_unsupported_decision_target_type_is_400(org):
    resp = org.post(
        "/api/decisions",
        json={"target_type": "not_a_real_type", "target_id": "x", "decision": "approve", "rationale": _RATIONALE},
    )
    # bad input, not a missing record: 400 (never a 500)
    assert resp.status_code == 400, resp.text

"""Governance decisions require substantive reviewer input (audit finding H4).

The dashboard submits a scaffolded decision packet ("Evidence reviewed: no ...
Reviewer rationale: not provided"). That scaffold alone used to satisfy the
server's min_length=1 guard, so a gate could be approved or an incident closed
with nothing typed. substantive_rationale strips the scaffold and rejects it.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.schemas.workflow import substantive_rationale  # noqa: E402

_EMPTY_PACKET = (
    "Evidence reviewed: no\n"
    "Policy basis checked: no\n"
    "Owner accountability confirmed: no\n"
    "Reviewer rationale: not provided"
)

_EMPTY_INCIDENT = (
    "Root cause: not documented\n"
    "Impact: not documented\n"
    "Remediation completed: not documented\n"
    "Recurrence prevention: not documented"
)

_REAL_PACKET = (
    "Evidence reviewed: yes\n"
    "Policy basis checked: yes\n"
    "Owner accountability confirmed: yes\n"
    "Reviewer rationale: Eval evidence covers the new prompt template and the "
    "residual jailbreak risk is accepted by the owning team."
)


def test_untouched_decision_packet_is_rejected():
    with pytest.raises(ValueError):
        substantive_rationale(_EMPTY_PACKET)


def test_untouched_incident_packet_is_rejected():
    with pytest.raises(ValueError):
        substantive_rationale(_EMPTY_INCIDENT)


def test_bare_placeholder_is_rejected():
    for value in ("", "   ", "n/a", "none", "tbd", "approved"):
        with pytest.raises(ValueError):
            substantive_rationale(value)


def test_packet_with_real_rationale_passes():
    assert substantive_rationale(_REAL_PACKET) == _REAL_PACKET


def test_gate_approval_with_empty_packet_is_422(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

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
    with TestClient(app) as org:
        login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
        # A non-existent gate still exercises schema validation, which runs first.
        resp = org.post(
            "/api/deployment-gates/does-not-exist/approve",
            json={"rationale": _EMPTY_PACKET},
        )
        assert resp.status_code == 422, resp.text

"""an agent more autonomous than its system's intake is a finding

intake records autonomy on a three-level scale that sets the risk tier; the
agent registry uses a five-level scale. the registry scale bands onto the
intake one (0 assistive, 1-2 supervised, 3-4 autonomous), and a registered
agent whose band is above what its system's live intake declares raises
RISK-AGT-INTAKE, because the system was reviewed at a lower tier than the
agent runs at
"""

from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.test_compliance_claims import _gov_user, _org  # noqa: E402


def _intake(gov, application: str, autonomy: str) -> dict:
    created = gov.post(
        "/api/intake",
        json={
            "application_name": application,
            "use_case": f"{application} use",
            "description": "d",
            "intended_purpose": "p",
            "data_sensitivity": "internal",
            "autonomy_level": autonomy,
            "project": "p1",
            "environment": "prod",
        },
    )
    assert created.status_code == 200, created.text
    return created.json()["intake"]


def _register(org, agent: str, application: str, level: int) -> None:
    registered = org.post(
        "/api/agent-registry",
        json={
            "agent_name": agent,
            "owner_ref": "owner@example.test",
            "application_name": application,
            "autonomy_level": level,
            "allowed_tools": [],
            "human_checkpoint": True,
        },
    )
    assert registered.status_code == 200, registered.text


def _run(tenant: str, agent: str, application: str, span: str) -> dict:
    return {
        "type": "agent.run",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "agent_name": agent,
            "step_count": 0,
            "outcome": "ok",
            "metadata": {"tenant_id": tenant, "application_name": application, "workflow_name": "wf"},
        },
    }


def _intake_findings(org) -> dict[str, dict]:
    return {
        r["rule_id"]: r
        for r in org.get("/api/risk-register").json()["risks"]
        if str(r.get("rule_id", "")).startswith("RISK-AGT-INTAKE")
    }


def test_intake_band_covers_every_registry_level():
    from app.storage.agents import AUTONOMY_LEVELS, INTAKE_AUTONOMY_FOR_LEVEL
    from app.storage.intake import AUTONOMY_LEVELS as INTAKE_LEVELS

    assert set(INTAKE_AUTONOMY_FOR_LEVEL) == set(AUTONOMY_LEVELS)
    assert set(INTAKE_AUTONOMY_FOR_LEVEL.values()) == set(INTAKE_LEVELS)
    bands = [INTAKE_LEVELS.index(INTAKE_AUTONOMY_FOR_LEVEL[level]) for level in sorted(AUTONOMY_LEVELS)]
    assert bands == sorted(bands), "the banding must preserve order"


def test_agent_above_its_intake_is_a_finding(super_admin_client):
    org, headers = _org(super_admin_client, "autonomy")
    gov = _gov_user(org, "autonomy")
    _intake(gov, "claims-app", "assistive")
    _intake(gov, "triage-app", "supervised")
    _intake(gov, "ops-app", "autonomous")
    _register(org, "claims-bot", "claims-app", 4)  # autonomous against assistive
    _register(org, "triage-bot", "triage-app", 2)  # supervised against supervised
    _register(org, "ops-bot", "ops-app", 3)  # autonomous against autonomous
    batch = [
        _run("autonomy", "claims-bot", "claims-app", "a"),
        _run("autonomy", "triage-bot", "triage-app", "b"),
        _run("autonomy", "ops-bot", "ops-app", "c"),
    ]
    assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200

    findings = _intake_findings(org)
    assert set(findings) == {"RISK-AGT-INTAKE:claims-bot"}
    finding = findings["RISK-AGT-INTAKE:claims-bot"]
    assert finding["status"] == "open"
    assert finding["evidence_summary"] == (
        "Agent 'claims-bot' is autonomy level 4 (autonomous); the intake for 'claims-app' declares assistive"
    )

    posture = {a["agent_name"]: a for a in org.get("/api/agents/posture").json()["agents"]}
    assert "agent_autonomy_exceeds_intake" in posture["claims-bot"]["issues"]
    assert "agent_autonomy_exceeds_intake" not in posture["triage-bot"]["issues"]
    registry = {a["agent_name"]: a for a in org.get("/api/agent-registry").json()["agents"]}
    assert registry["claims-bot"]["intake_autonomy"] == "autonomous"
    assert registry["triage-bot"]["intake_autonomy"] == "supervised"
    org.close()
    gov.close()


def test_retired_intake_and_missing_intake_do_not_count(super_admin_client):
    org, headers = _org(super_admin_client, "retiredintake")
    gov = _gov_user(org, "retiredintake")
    retired = _intake(gov, "old-app", "assistive")
    assert gov.post(f"/api/intake/{retired['intake_id']}/retire", json={"rationale": "decommissioned"}).status_code == 200
    _register(org, "old-bot", "old-app", 4)
    _register(org, "loose-bot", "no-intake-app", 4)
    batch = [
        _run("retiredintake", "old-bot", "old-app", "a"),
        _run("retiredintake", "loose-bot", "no-intake-app", "b"),
    ]
    assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200
    assert _intake_findings(org) == {}
    org.close()
    gov.close()

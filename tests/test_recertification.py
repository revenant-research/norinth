"""per-tier recertification clocks: the maintenance worker opens review work
when a certified system ages past its tier's window, and the lifecycle
endpoints close that work when the clock restarts"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

INTAKE = {
    "application_name": "Claims",
    "use_case": "Claims triage",
    "description": "d",
    "intended_purpose": "p",
    "data_sensitivity": "restricted",
    "autonomy_level": "supervised",
    "affects_individuals": True,
    "project": "p1",
    "environment": "prod",
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
    try:
        yield client
    finally:
        client.close()


def _approved_use_case(org):
    from app.main import app
    from fastapi.testclient import TestClient

    assert org.post("/api/intake", json=INTAKE).status_code == 200
    org.post("/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev", "password": "rev-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "rev@acme.test", "role": "governance_admin"})
    task = next(t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "intake_review")
    with TestClient(app) as reviewer:
        login_and_activate(reviewer, "rev@acme.test", "rev-password-1")
        decided = reviewer.post(
            "/api/decisions",
            json={
                "target_type": "review_task",
                "target_id": task["task_id"],
                "decision": "approve",
                "rationale": "Intake evidence reviewed; risk tier is appropriate.",
            },
        )
        assert decided.status_code == 200, decided.text
    return next(r for r in org.get("/api/intake").json()["intake"] if r["application_name"] == "Claims")


def _age(intake_id: str, timestamp: str = "2020-01-01 00:00:00") -> None:
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute("UPDATE ai_use_cases SET updated_at = ? WHERE intake_id = ?", (timestamp, intake_id))


def _recert_policy(days=180):
    return {
        "schema": "governance-policy/v1",
        "intake": {"tiers": {"high": {"stages": [{"role": "governance_reviewer"}], "recertify_days": days}}},
    }


def test_default_policy_has_no_recertification_clock(org):
    """equivalence pin: without a tenant policy, an approved system never ages
    into recertification — exactly pre-policy behavior"""
    from app.services.maintenance import run_once

    record = _approved_use_case(org)
    _age(record["intake_id"])
    assert run_once()["recertifications_opened"] == 0
    tasks = org.get("/api/review-tasks").json()["review_tasks"]
    assert not [t for t in tasks if t["task_type"] == "recertification_review"]


def test_policy_clock_opens_routed_review_once_per_certification(org):
    from app.services.maintenance import run_once

    draft = org.post("/api/governance-policy/draft", json={"body": _recert_policy()})
    version = draft.json()["policy"]["version"]
    assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200

    record = _approved_use_case(org)
    _age(record["intake_id"])
    assert run_once()["recertifications_opened"] == 1
    # idempotent: the same certification is asked about once
    assert run_once()["recertifications_opened"] == 0

    tasks = [t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "recertification_review"]
    assert len(tasks) == 1
    task = tasks[0]
    assert task["status"] == "open"
    assert "recertification every 180 days" in task["rationale"]
    # routed by the seeded queue policy for recertification work
    assert task["assigned_role"] == "governance_admin"
    assert task["assigned_to"] == "rev@acme.test"

    # recertifying closes the reminder and restarts the clock
    recertified = org.post(
        f"/api/intake/{record['intake_id']}/recertify", json={"rationale": "Annual review completed."}
    )
    assert recertified.status_code == 200, recertified.text
    assert recertified.json()["intake"]["status"] == "recertified"
    tasks = [t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "recertification_review"]
    assert tasks[0]["status"] == "closed"
    assert run_once()["recertifications_opened"] == 0

    # ...and a recertified system ages again under the same clock
    _age(record["intake_id"], "2021-01-01 00:00:00")
    assert run_once()["recertifications_opened"] == 1


def test_retirement_closes_open_recertification_work(org):
    from app.services.maintenance import run_once

    draft = org.post("/api/governance-policy/draft", json={"body": _recert_policy()})
    version = draft.json()["policy"]["version"]
    org.post(f"/api/governance-policy/versions/{version}/activate")
    record = _approved_use_case(org)
    _age(record["intake_id"])
    assert run_once()["recertifications_opened"] == 1

    retired = org.post(f"/api/intake/{record['intake_id']}/retire", json={"rationale": "Replaced by v2 system."})
    assert retired.status_code == 200, retired.text
    tasks = [t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "recertification_review"]
    assert tasks[0]["status"] == "closed"
    # a retired system never re-enters the clock
    assert run_once()["recertifications_opened"] == 0

"""vendor registry: review through the stage machinery, telemetry-proven
posture (RISK-VND-001), model allow-lists, and recertification aging"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}
BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}
RATIONALE = "Vendor posture and terms reviewed against policy."


def _model_call(span: str, provider: str = "openai", model: str = "gpt-4o") -> dict:
    return {
        **BASE,
        "type": "model.call",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": "2026-08-22T00:00:00Z",
        "attributes": {
            "provider": provider,
            "model": model,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "metadata": META,
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
    token = client.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    try:
        yield client, {"Authorization": f"Bearer {token}"}
    finally:
        client.close()


def _reviewer(org_client, email="rev@acme.test", role="governance_reviewer"):
    from app.main import app
    from fastapi.testclient import TestClient

    org_client.post("/api/org/users", json={"email": email, "display_name": email, "password": "rev-password-1"})
    org_client.post("/api/org/role-assignments", json={"user_ref": email, "role": role})
    client = TestClient(app)
    # first sign-in rotates the password; later sign-ins use the rotated one
    login = client.post("/api/auth/login", json={"email": email, "password": "rev-password-1"})
    if login.status_code != 200:
        login_and_activate(client, email, "rev-password-1-rotated-1")
    elif login.json()["user"].get("must_change_password"):
        client.post(
            "/api/auth/change-password",
            json={"current_password": "rev-password-1", "new_password": "rev-password-1-rotated-1"},
        )
    return client


def _vnd_findings(client):
    return [r for r in client.get("/api/risk-register").json()["risks"] if r["rule_id"].startswith("RISK-VND-001")]


def test_unreviewed_provider_raises_finding_and_approval_covers_it(org):
    client, headers = org
    assert client.post("/v1/events/batch", json={"events": [_model_call("m1")]}, headers=headers).status_code == 200

    # openai is in production with no vendor entry: telemetry proves the gap
    findings = _vnd_findings(client)
    assert len(findings) == 1
    assert "no approved vendor entry" in findings[0]["evidence_summary"]
    assert findings[0]["application_name"] == "Claims"
    assert findings[0]["evidence_trace_ids"]

    coverage = client.get("/api/vendors").json()["coverage"]
    assert coverage["summary"] == {"observed_providers": 1, "covered": 0, "uncovered": 1, "registered_vendors": 0}

    # register and review the vendor through the stage machinery; the submitter
    # is a governance_admin so it holds review.decide, which lets the test
    # prove the maker-checker rule rather than a missing permission
    with _reviewer(client, email="ga@acme.test", role="governance_admin") as ga:
        created = ga.post("/api/vendors", json={"name": "OpenAI", "providers": ["OpenAI"]})
        assert created.status_code == 200, created.text
        vendor = created.json()["vendor"]
        assert vendor["status"] == "draft"
        assert vendor["providers"] == ["openai"]  # normalized

        submitted = ga.post(f"/api/vendors/{vendor['vendor_id']}/submit-review")
        assert submitted.status_code == 200, submitted.text
        under_review = submitted.json()["vendor"]
        assert under_review["status"] == "under_review"
        stages = under_review["stages"]
        assert len(stages) == 1 and stages[0]["status"] == "open"
        assert stages[0]["policy_tenant"] == ""  # governed by the platform default

        # the submitter (maker) cannot decide the vendor review
        blocked = ga.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide",
            json={"decision": "approve", "rationale": RATIONALE},
        )
        assert blocked.status_code == 403
        assert "Segregation of duties" in blocked.json()["detail"]

    with _reviewer(client) as reviewer:
        approved = reviewer.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide",
            json={"decision": "approve", "rationale": RATIONALE},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["subject_status"] == "approved"

    vendors = client.get("/api/vendors").json()
    assert vendors["vendors"][0]["status"] == "approved"
    assert vendors["vendors"][0]["reviewed_at"]
    assert vendors["coverage"]["summary"]["covered"] == 1

    # new telemetry no longer raises a fresh finding for the covered provider;
    # the earlier finding stays for a human to close (findings never auto-close)
    assert client.post("/v1/events/batch", json={"events": [_model_call("m2")]}, headers=headers).status_code == 200
    assert len(_vnd_findings(client)) == 1


def test_model_outside_allow_list_raises_finding(org):
    client, headers = org
    created = client.post(
        "/api/vendors",
        json={"name": "OpenAI", "providers": ["openai"], "approved_models": ["gpt-4o"]},
    )
    vendor = created.json()["vendor"]
    client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review")
    stages = client.get("/api/vendors").json()["vendors"][0]["stages"]
    with _reviewer(client) as reviewer:
        reviewer.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide",
            json={"decision": "approve", "rationale": RATIONALE},
        )

    # an approved model raises nothing; an off-list model is a finding
    assert client.post("/v1/events/batch", json={"events": [_model_call("ok", model="gpt-4o")]}, headers=headers).status_code == 200
    assert _vnd_findings(client) == []
    assert client.post("/v1/events/batch", json={"events": [_model_call("off", model="o3-preview")]}, headers=headers).status_code == 200
    findings = _vnd_findings(client)
    assert len(findings) == 1
    assert "outside vendor" in findings[0]["evidence_summary"]
    assert "o3-preview" in findings[0]["evidence_summary"]

    coverage = client.get("/api/vendors").json()["coverage"]
    provider_row = coverage["providers"][0]
    assert provider_row["covered"] is True
    assert provider_row["disallowed_models"] == ["o3-preview"]


def test_vendor_rejection_and_re_review_rounds(org):
    client, _ = org
    vendor = client.post("/api/vendors", json={"name": "Mistral", "providers": ["mistral"]}).json()["vendor"]
    client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review")
    stages = client.get("/api/vendors").json()["vendors"][0]["stages"]
    with _reviewer(client) as reviewer:
        rejected = reviewer.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide",
            json={"decision": "reject", "rationale": RATIONALE},
        )
        assert rejected.status_code == 200
        assert rejected.json()["subject_status"] == "rejected"

    # a second round gets fresh stages; the first round's stage is untouched evidence
    resubmitted = client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review")
    assert resubmitted.status_code == 200, resubmitted.text
    second_round = resubmitted.json()["vendor"]
    assert second_round["review_round"] == 2
    assert len(second_round["stages"]) == 1
    assert second_round["stages"][0]["status"] == "open"
    assert second_round["stages"][0]["stage_id"] != stages[0]["stage_id"]

    from app.storage.policy_engine import stages_for_subject

    first_round = stages_for_subject("vendor_review", vendor["vendor_id"], 1)
    assert first_round[0]["status"] == "rejected"

    # a reviewer who decided round 1 may decide round 2: the distinct-decider
    # rule is per review, not per lifetime
    with _reviewer(client) as reviewer:
        approved = reviewer.post(
            f"/api/approval-stages/{second_round['stages'][0]['stage_id']}/decide",
            json={"decision": "approve", "rationale": RATIONALE},
        )
        assert approved.status_code == 200, approved.text
    assert client.get("/api/vendors").json()["vendors"][0]["status"] == "approved"


def test_vendor_recertification_ages_out_by_policy(org):
    client, _ = org
    vendor = client.post("/api/vendors", json={"name": "OpenAI", "providers": ["openai"]}).json()["vendor"]
    client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review")
    stages = client.get("/api/vendors").json()["vendors"][0]["stages"]
    with _reviewer(client) as reviewer:
        reviewer.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide",
            json={"decision": "approve", "rationale": RATIONALE},
        )

    # age the approval past the default 365-day vendor window
    from app.services.maintenance import run_once
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute(
            "UPDATE vendor_registry SET reviewed_at = '2020-01-01 00:00:00' WHERE vendor_id = ?",
            (vendor["vendor_id"],),
        )
    result = run_once()
    assert result["vendor_recertifications_due"] == 1
    refreshed = client.get("/api/vendors").json()
    assert refreshed["vendors"][0]["status"] == "recertify_due"
    # a lapsed vendor no longer covers its providers
    assert refreshed["coverage"]["summary"]["covered"] == 0
    # the flip is audited and idempotent
    entries = client.get("/api/audit-logs?action=vendor.recertify_due").json()["audit_logs"]
    assert len(entries) == 1
    assert run_once()["vendor_recertifications_due"] == 0


def test_vendor_write_permissions(org):
    client, _ = org
    with _reviewer(client, email="viewer@acme.test", role="governance_viewer") as viewer:
        # members can read the registry; only config.write can change it
        assert viewer.get("/api/vendors").status_code == 200
        assert viewer.post("/api/vendors", json={"name": "X", "providers": ["x"]}).status_code == 403
    vendor = client.post("/api/vendors", json={"name": "X", "providers": ["x"]}).json()["vendor"]
    with _reviewer(client, email="viewer2@acme.test", role="governance_viewer") as viewer:
        assert viewer.post(f"/api/vendors/{vendor['vendor_id']}/retire").status_code == 403
    retired = client.post(f"/api/vendors/{vendor['vendor_id']}/retire")
    assert retired.status_code == 200
    assert retired.json()["vendor"]["status"] == "retired"

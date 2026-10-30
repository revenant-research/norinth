"""configuration that changes what a release gate requires is on the audit chain

a config.write holder can override a control's evidence requirements, reroute
findings to a different owner role, or change review routing. risk rules and
retention at the same layer were audited; these three were not, so the gate
requirements could be loosened with no chain row. the listing endpoints also
answered with the platform defaults only, so an organization could not see the
policies in force for it
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import login_and_activate


def _org(super_admin_client, tenant_id: str = "acme"):
    from app.main import app

    email, password = f"oa@{tenant_id}.test", f"{tenant_id}-oa-pw-1"
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant_id,
            "name": tenant_id.title(),
            "admin_email": email,
            "admin_display_name": "OA",
            "admin_password": password,
        },
    )
    org = TestClient(app)
    org.__enter__()
    login_and_activate(org, email, password)
    return org


def _audit_rows(tenant_id: str, action: str) -> list[dict]:
    import json

    from app.storage.audit import list_audit_logs

    rows = list_audit_logs(tenant_id=tenant_id, action=action)
    return [{**row, "detail": json.loads(row["detail"] or "{}")} for row in rows]


def test_control_override_is_audited_with_its_requirements(super_admin_client):
    org = _org(super_admin_client)
    sample = org.get("/api/control-catalog").json()["controls"][0]["control_id"]
    body = {
        "control_id": sample,
        "name": "Loosened",
        "evidence_event_types": ["model.call"],
        "required_fields": [],
        "rationale": "pilot",
    }
    assert org.post("/api/control-catalog", json=body).status_code == 200

    (entry,) = _audit_rows("acme", "control.configure")
    assert entry["actor_ref"] == "oa@acme.test"
    assert entry["target_type"] == "control" and entry["target_id"] == sample
    assert entry["detail"]["required_fields"] == []
    assert entry["detail"]["evidence_event_types"] == ["model.call"]
    org.close()


def test_owner_policy_change_is_audited_and_listed_for_the_tenant(super_admin_client):
    org = _org(super_admin_client)
    assert (
        org.post(
            "/api/owner-policies",
            json={"policy_id": "p1", "subject_type": "application", "owner_role": "business_owner"},
        ).status_code
        == 200
    )

    (entry,) = _audit_rows("acme", "owner_policy.configure")
    assert entry["target_id"] == "p1" and entry["detail"]["owner_role"] == "business_owner"

    listed = {policy["policy_id"]: policy for policy in org.get("/api/owner-policies").json()["owner_policies"]}
    assert listed["p1"]["tenant_id"] == "acme"
    assert listed["p1"]["owner_role"] == "business_owner"
    org.close()


def test_review_queue_policy_change_is_audited_and_listed_for_the_tenant(super_admin_client):
    org = _org(super_admin_client)
    assert (
        org.post(
            "/api/review-queue-policies",
            json={
                "policy_id": "intake",
                "task_type": "intake_review",
                "assigned_role": "org_admin",
                "due_days": 2,
                "escalation_days": 5,
            },
        ).status_code
        == 200
    )

    (entry,) = _audit_rows("acme", "review_queue_policy.configure")
    assert entry["target_id"] == "intake"
    assert entry["detail"] == {
        "task_type": "intake_review",
        "assigned_role": "org_admin",
        "due_days": 2,
        "escalation_days": 5,
    }

    listed = {
        policy["policy_id"]: policy for policy in org.get("/api/review-queue-policies").json()["review_queue_policies"]
    }
    assert listed["intake"]["tenant_id"] == "acme" and listed["intake"]["due_days"] == 2
    org.close()


def test_one_tenants_policies_are_not_listed_for_another(super_admin_client):
    acme = _org(super_admin_client, "acme")
    beta = _org(super_admin_client, "beta")
    assert (
        acme.post(
            "/api/owner-policies",
            json={"policy_id": "acme-only", "subject_type": "application", "owner_role": "business_owner"},
        ).status_code
        == 200
    )
    assert "acme-only" in {p["policy_id"] for p in acme.get("/api/owner-policies").json()["owner_policies"]}
    assert "acme-only" not in {p["policy_id"] for p in beta.get("/api/owner-policies").json()["owner_policies"]}
    acme.close()
    beta.close()

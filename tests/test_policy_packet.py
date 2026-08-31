"""the audit packet proves which policy governed each decision: active body
with its hash, version history, stage records, and the vendor registry"""

from __future__ import annotations

import pathlib
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def test_packet_carries_policy_stages_and_vendors(super_admin_client):
    from app.main import app

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
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")

    two_stage = {
        "schema": "governance-policy/v1",
        "intake": {
            "tiers": {
                "high": {
                    "stages": [{"role": "governance_reviewer"}, {"role": "risk_owner"}],
                    "mode": "sequence",
                }
            }
        },
    }
    draft = org.post("/api/governance-policy/draft", json={"body": two_stage})
    version = draft.json()["policy"]["version"]
    body_hash = draft.json()["policy"]["body_hash"]
    assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200

    submitted = org.post(
        "/api/intake",
        json={
            "application_name": "Claims",
            "use_case": "Claims triage",
            "description": "d",
            "intended_purpose": "p",
            "data_sensitivity": "restricted",
            "autonomy_level": "supervised",
            "affects_individuals": True,
            "project": "p1",
            "environment": "prod",
        },
    )
    assert submitted.status_code == 200
    org.post("/api/vendors", json={"name": "OpenAI", "providers": ["openai"]})

    packet = org.get("/api/compliance/audit-packet").json()

    # the policy section: the active body, its hash, and the anchored history
    policy = packet["governance_policy"]
    assert policy["active"]["version"] == version
    assert policy["active"]["body_hash"] == body_hash
    assert policy["active"]["source"] == "tenant"
    history = {row["version"]: row for row in policy["history"]}
    assert history[version]["status"] == "active"
    assert history[version]["body_hash"] == body_hash
    assert history[version]["activated_at"]

    # every stage record pins the policy that materialized it
    stages = packet["approval_stages"]
    assert len(stages) == 2
    assert all(s["policy_tenant"] == "acme" and s["policy_version"] == version for s in stages)

    # the vendor registry and its telemetry reconciliation ride along
    assert packet["vendor_registry"][0]["name"] == "OpenAI"
    assert "summary" in packet["vendor_coverage"]

    # exporting the packet is itself audited, and the chain still verifies
    from app.storage.audit import verify_audit_chain

    assert verify_audit_chain()["ok"] is True
    org.close()

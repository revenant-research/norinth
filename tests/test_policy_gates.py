"""gate requirements from governance policy: attestation per environment,
tighten-only semantics, and the policy version pinned on the gate snapshot"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}
BASE = {"schema_version": "2026-01", "service": "claims-ci", "environment": "prod", "project": "p1"}

APPROVAL_RATIONALE = "Release evidence reviewed and bound to this version."


def _deployment() -> dict:
    return {
        **BASE,
        "type": "deployment.event",
        "trace_id": "trc_dep_v1",
        "span_id": "spn_dep_v1",
        "timestamp": "2026-08-22T00:00:02Z",
        "attributes": {
            "deployment_id": "dep-1",
            "version": "v1",
            "artifact_ref": "img:v1",
            "provider": "openai",
            "model": "gpt-4o",
            "prompt_version": "p1",
            "deployment_status": "pending",
            "deployed_by": "ci@acme.test",
            "metadata": META,
        },
    }


def _prompt() -> dict:
    return {
        **BASE,
        "type": "prompt.event",
        "trace_id": "trc_prompt",
        "span_id": "spn_prompt",
        "timestamp": "2026-08-22T00:00:01Z",
        "attributes": {"prompt_id": "triage-prompt", "version": "p1", "artifact_ref": "prompt:p1", "template": {"t": "x"}, "metadata": META},
    }


def _eval(span: str) -> dict:
    return {
        **BASE,
        "type": "eval.result",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": "2026-08-22T00:00:03Z",
        "status": "success",
        "attributes": {
            "eval_id": "safety-suite",
            "passed": True,
            "score": 0.97,
            "prompt_version": "p1",
            "artifact_ref": "img:v1",
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
    token = client.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
    try:
        yield client, {"Authorization": f"Bearer {token}"}
    finally:
        client.close()


def _approver(org_client):
    from app.main import app
    from fastapi.testclient import TestClient

    org_client.post("/api/org/users", json={"email": "ga@acme.test", "display_name": "GA", "password": "ga-password-1"})
    org_client.post("/api/org/role-assignments", json={"user_ref": "ga@acme.test", "role": "governance_admin"})
    client = TestClient(app)
    login_and_activate(client, "ga@acme.test", "ga-password-1")
    return client


def _activate(org_client, body):
    draft = org_client.post("/api/governance-policy/draft", json={"body": body})
    assert draft.status_code == 200, draft.text
    version = draft.json()["policy"]["version"]
    assert org_client.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200
    return version


def _gate(client) -> dict:
    gates = client.get("/api/deployment-gates").json()["deployment_gates"]
    assert len(gates) == 1, gates
    return gates[0]


def _gates_policy(environment: str, require_attested: bool) -> dict:
    return {
        "schema": "governance-policy/v1",
        "gates": {"environments": {environment: {"require_attested_evals": require_attested, "max_open_material_changes": 0}}},
    }


def test_default_policy_keeps_unattested_evals_passing(org):
    """equivalence pin: with no tenant policy and no attestation keys, an
    unattested passing eval still satisfies the gate — exactly pre-policy
    behavior — and the gate records the default policy version it consulted"""
    client, headers = org
    resp = client.post("/v1/events/batch", json={"events": [_prompt(), _deployment(), _eval("plain")]}, headers=headers)
    assert resp.status_code == 200, resp.text
    gate = _gate(client)
    assert gate["passing_eval_count"] == 1
    assert gate["policy_tenant"] == "" and gate["policy_version"] == 1
    with _approver(client) as approver:
        approved = approver.post(f"/api/deployment-gates/{gate['gate_id']}/approve", json={"rationale": APPROVAL_RATIONALE})
        assert approved.status_code == 200, approved.text


def test_policy_can_require_attestation_per_environment(org):
    """a tenant policy demanding attested evals for prod blocks unattested
    evidence even though no attestation key exists; the requirement reads per
    environment with '*' as the fallback"""
    client, headers = org
    version = _activate(client, _gates_policy("prod", True))
    resp = client.post("/v1/events/batch", json={"events": [_prompt(), _deployment(), _eval("plain")]}, headers=headers)
    assert resp.status_code == 200, resp.text
    gate = _gate(client)
    # the unattested eval no longer counts, and the gate names the tenant policy
    assert gate["passing_eval_count"] == 0
    assert "attested" in gate["required_reason"]
    assert gate["policy_tenant"] == "acme" and gate["policy_version"] == version
    with _approver(client) as approver:
        blocked = approver.post(f"/api/deployment-gates/{gate['gate_id']}/approve", json={"rationale": APPROVAL_RATIONALE})
        assert blocked.status_code == 400
        assert "attested" in blocked.json()["detail"]


def test_environment_entries_fall_back_to_star_then_default(org):
    client, headers = org
    # policy tightens only staging; prod falls through the tenant's '*'
    body = {
        "schema": "governance-policy/v1",
        "gates": {
            "environments": {
                "staging": {"require_attested_evals": True},
                "*": {"require_attested_evals": False},
            }
        },
    }
    _activate(client, body)
    resp = client.post("/v1/events/batch", json={"events": [_prompt(), _deployment(), _eval("plain")]}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert _gate(client)["passing_eval_count"] == 1


def test_policy_cannot_relax_below_registered_keys(org):
    """once attestation keys exist, a policy declaring require_attested_evals
    false does not switch the requirement off: policy only tightens"""
    from norinth_logger.attest import generate_keypair, sign_eval_result

    client, headers = org
    private_pem, public_pem = generate_keypair()
    key_id = client.post("/api/attestation-keys", json={"name": "ci", "public_key_pem": public_pem}).json()[
        "attestation_key"
    ]["key_id"]
    _activate(client, _gates_policy("*", False))

    unsigned = _eval("plain")
    signed = sign_eval_result(_eval("signed"), private_key_pem=private_pem, key_id=key_id)
    resp = client.post("/v1/events/batch", json={"events": [_prompt(), _deployment(), unsigned, signed]}, headers=headers)
    assert resp.status_code == 200, resp.text
    # only the signed eval counts: the keys-based requirement stands
    assert _gate(client)["passing_eval_count"] == 1


def test_material_change_ceiling_cannot_be_relaxed(org):
    client, _ = org
    relaxed = {
        "schema": "governance-policy/v1",
        "gates": {"environments": {"prod": {"max_open_material_changes": 2}}},
    }
    refused = client.post("/api/governance-policy/draft", json={"body": relaxed})
    assert refused.status_code == 400
    assert "cannot exceed" in refused.json()["detail"]

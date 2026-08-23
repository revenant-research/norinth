"""Signed eval evidence (audit roadmap #20, C-2 hardening).

Covers:
- SDK and platform produce byte-identical canonical statements.
- A valid Ed25519 attestation marks the eval ``attested``; the client can never
  self-assert ``attested``.
- Forged / tampered / cross-tenant / unknown / revoked attestations reject the
  batch and are audit-logged.
- Once an organization registers a key, only attested passing evals satisfy a
  deployment gate; before that, behaviour is unchanged.
- Attestation key management is org-admin only and tenant-bound.
"""

from __future__ import annotations

import base64
import copy
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}
BASE = {"schema_version": "2026-01", "service": "claims-ci", "environment": "prod", "project": "p1"}


def _deployment(version: str = "v1") -> dict:
    return {
        **BASE,
        "type": "deployment.event",
        "trace_id": f"trc_dep_{version}",
        "span_id": f"spn_dep_{version}",
        "timestamp": "2026-08-22T00:00:02Z",
        "attributes": {
            "deployment_id": "dep-1",
            "version": version,
            "artifact_ref": f"img:{version}",
            "provider": "openai",
            "model": "gpt-4o",
            "prompt_version": "p1",
            "deployment_status": "pending",
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


def _eval(span: str, passed: bool = True) -> dict:
    return {
        **BASE,
        "type": "eval.result",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": "2026-08-22T00:00:03Z",
        "status": "success",
        "attributes": {
            "eval_id": "safety-suite",
            "passed": passed,
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


def _keypair():
    from norinth_logger.attest import generate_keypair

    return generate_keypair()


def _gate(client) -> dict:
    gates = client.get("/api/deployment-gates").json()["deployment_gates"]
    assert len(gates) == 1, gates
    return gates[0]


# --- statement parity -------------------------------------------------------------


def test_sdk_and_platform_statements_are_identical():
    from app.services.attestation import build_eval_statement as platform_statement
    from norinth_logger.attest import build_eval_statement as sdk_statement

    event = _eval("parity")
    assert sdk_statement(event) == platform_statement(event)
    assert b'"type":"norinth.eval.attestation/v1"' in sdk_statement(event)
    # Every replay-relevant field is bound into the statement.
    for field in ("acme", "Claims", "triage", "safety-suite", "trc_parity", "spn_parity", "img:v1", "p1"):
        assert field.encode() in sdk_statement(event)


# --- ingestion ----------------------------------------------------------------------


def test_valid_attestation_marks_eval_attested_and_client_cannot_self_assert(org):
    from norinth_logger.attest import sign_eval_result

    client, headers = org
    private_pem, public_pem = _keypair()
    key = client.post("/api/attestation-keys", json={"name": "GitHub Actions", "public_key_pem": public_pem}).json()
    key_id = key["attestation_key"]["key_id"]

    signed = sign_eval_result(_eval("signed"), private_key_pem=private_pem, key_id=key_id)
    # A client claiming attested=true without a signature is stripped, not trusted.
    forged_flag = _eval("selfassert")
    forged_flag["attributes"]["attested"] = True
    forged_flag["attributes"]["attested_key_id"] = key_id

    resp = client.post("/v1/events/batch", json={"events": [signed, forged_flag]}, headers=headers)
    assert resp.status_code == 200, resp.text

    evals = {e["span_id"]: e for e in client.get("/api/events").json()["events"] if e["type"] == "eval.result"}
    assert evals["spn_signed"]["attributes"]["attested"] is True
    assert evals["spn_signed"]["attributes"]["attested_key_id"] == key_id
    assert evals["spn_selfassert"]["attributes"]["attested"] is False
    assert "attested_key_id" not in evals["spn_selfassert"]["attributes"]

    keys = client.get("/api/attestation-keys").json()
    assert keys["attestation_required"] is True
    assert keys["attestation_keys"][0]["last_used_at"]


def test_tampered_unknown_cross_tenant_and_revoked_attestations_are_rejected(org, super_admin_client):
    from norinth_logger.attest import sign_eval_result

    client, headers = org
    private_pem, public_pem = _keypair()
    key_id = client.post("/api/attestation-keys", json={"name": "ci", "public_key_pem": public_pem}).json()[
        "attestation_key"
    ]["key_id"]

    # 1) Signature over passed=False, then flipped to True after signing.
    tampered = sign_eval_result(_eval("tamper", passed=False), private_key_pem=private_pem, key_id=key_id)
    tampered["attributes"]["passed"] = True
    resp = client.post("/v1/events/batch", json={"events": [tampered]}, headers=headers)
    assert resp.status_code == 400 and "does not match" in resp.text

    # 2) Valid signature re-used on a different span (replay onto another run).
    original = sign_eval_result(_eval("orig"), private_key_pem=private_pem, key_id=key_id)
    replay = copy.deepcopy(original)
    replay["span_id"] = "spn_replay"
    replay["trace_id"] = "trc_replay"
    resp = client.post("/v1/events/batch", json={"events": [replay]}, headers=headers)
    assert resp.status_code == 400 and "does not match" in resp.text

    # 3) Unknown key id.
    unknown = sign_eval_result(_eval("unknown"), private_key_pem=private_pem, key_id="nak_doesnotexist")
    resp = client.post("/v1/events/batch", json={"events": [unknown]}, headers=headers)
    assert resp.status_code == 400 and "unknown, revoked, or belongs to another organization" in resp.text

    # 4) Garbage signature.
    garbage = _eval("garbage")
    garbage["attributes"]["attestation"] = {"key_id": key_id, "signature": base64.b64encode(b"nope").decode()}
    resp = client.post("/v1/events/batch", json={"events": [garbage]}, headers=headers)
    assert resp.status_code == 400

    # 5) Another organization's key cannot attest acme's evidence even with a
    #    correct signature, because lookup is tenant-bound.
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "beta",
            "name": "Beta",
            "admin_email": "oa@beta.test",
            "admin_display_name": "OB",
            "admin_password": "ob-password-1",
        },
    )
    beta_private, beta_public = _keypair()
    with TestClient(app) as beta:
        login_and_activate(beta, "oa@beta.test", "ob-password-1")
        beta_key_id = beta.post("/api/attestation-keys", json={"name": "beta-ci", "public_key_pem": beta_public}).json()[
            "attestation_key"
        ]["key_id"]
    cross = sign_eval_result(_eval("cross"), private_key_pem=beta_private, key_id=beta_key_id)
    resp = client.post("/v1/events/batch", json={"events": [cross]}, headers=headers)
    assert resp.status_code == 400 and "belongs to another organization" in resp.text

    # 6) Revoked key: evidence signed with it is rejected from then on.
    assert client.post(f"/api/attestation-keys/{key_id}/revoke").status_code == 200
    after_revoke = sign_eval_result(_eval("revoked"), private_key_pem=private_pem, key_id=key_id)
    resp = client.post("/v1/events/batch", json={"events": [after_revoke]}, headers=headers)
    assert resp.status_code == 400

    # Every rejection is on the audit trail.
    logs = client.get("/api/audit-logs", params={"action": "evidence.attestation_rejected", "limit": 50}).json()
    assert logs["page"]["total"] >= 6
    assert all(entry["tenant_id"] == "acme" for entry in logs["audit_logs"])

    # Nothing from the rejected batches was stored.
    spans = {e["span_id"] for e in client.get("/api/events").json()["events"]}
    assert not spans & {"spn_tamper", "spn_replay", "spn_unknown", "spn_garbage", "spn_cross", "spn_revoked"}


# --- gate policy --------------------------------------------------------------------


def test_gate_counts_only_attested_evals_once_a_key_is_registered(org):
    from norinth_logger.attest import sign_eval_result

    client, headers = org
    # Before any key exists: a plain passing eval satisfies the evidence check.
    resp = client.post("/v1/events/batch", json={"events": [_prompt(), _deployment(), _eval("plain")]}, headers=headers)
    assert resp.status_code == 200, resp.text
    gate = _gate(client)
    assert gate["passing_eval_count"] == 1
    assert "missing passing eval evidence" not in (gate.get("required_reason") or "")

    # Register a key: the existing unattested eval no longer counts.
    private_pem, public_pem = _keypair()
    key_id = client.post("/api/attestation-keys", json={"name": "ci", "public_key_pem": public_pem}).json()[
        "attestation_key"
    ]["key_id"]
    resp = client.post("/v1/events/batch", json={"events": [_deployment("v1")]}, headers=headers)  # recompute
    assert resp.status_code == 200
    gate = _gate(client)
    assert gate["passing_eval_count"] == 0
    assert "missing attested passing eval evidence" in (gate.get("required_reason") or "")

    # An attested passing eval satisfies it again.
    signed = sign_eval_result(_eval("attested"), private_key_pem=private_pem, key_id=key_id)
    resp = client.post("/v1/events/batch", json={"events": [signed]}, headers=headers)
    assert resp.status_code == 200, resp.text
    gate = _gate(client)
    assert gate["passing_eval_count"] == 1


# --- key management RBAC ----------------------------------------------------------


def test_attestation_key_management_is_org_admin_and_tenant_bound(org, super_admin_client):
    client, _ = org
    _, public_pem = _keypair()
    # Super admins operate on organizations, not on tenant evidence keys.
    assert super_admin_client.get("/api/attestation-keys").status_code == 403
    # Garbage keys are rejected before anything is stored.
    bad = client.post("/api/attestation-keys", json={"name": "x", "public_key_pem": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"})
    assert bad.status_code == 400
    # RSA keys are refused: the contract is Ed25519 only.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    assert client.post("/api/attestation-keys", json={"name": "rsa", "public_key_pem": rsa_pem}).status_code == 400

    created = client.post("/api/attestation-keys", json={"name": "ci", "public_key_pem": public_pem}).json()["attestation_key"]
    assert created["fingerprint"].startswith("sha256:")
    assert created["status"] == "active"

    # A reviewer without config.write cannot manage keys.
    from app.main import app
    from fastapi.testclient import TestClient

    client.post("/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev", "password": "rev-password-1"})
    client.post("/api/org/role-assignments", json={"user_ref": "rev@acme.test", "role": "governance_reviewer"})
    with TestClient(app) as reviewer:
        login_and_activate(reviewer, "rev@acme.test", "rev-password-1")
        assert reviewer.post("/api/attestation-keys", json={"name": "x", "public_key_pem": public_pem}).status_code == 403
        assert reviewer.post(f"/api/attestation-keys/{created['key_id']}/revoke").status_code == 403

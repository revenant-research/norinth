# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Exercise the public contract as an independent job runner and evidence collector."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.helpers import login_and_activate

SCOPES = [
    "systems:read",
    "systems:write",
    "revisions:write",
    "observations:write",
    "authorizations:request",
    "receipts:write",
]
RATIONALE = {"rationale": "Reviewed the exact scope, evidence, and accountable operating conditions."}
MANIFEST = {
    "revision": "r1",
    "artifact_digest": "sha256:" + "a" * 64,
    "models": ["provider/model"],
    "tools": ["fetch-record"],
    "resources": ["record-store"],
    "human_checkpoint": True,
}
CAPABILITY = {
    "name": "disable-trigger",
    "resource_type": "job",
    "operation": "disable",
    "verification_check": "trigger-disabled",
    "reversible": True,
}
SYSTEM = {
    "external_id": "job-42",
    "display_name": "Document processing",
    "resource_type": "job",
    "purpose": "Process documents",
}


def ok(response):
    assert response.status_code == 200, response.text
    return response.json()


def user(admin, email, role):
    from app.main import app

    password = "temporary-password-1234"
    ok(admin.post("/api/org/users", json={"email": email, "display_name": email, "password": password}))
    ok(admin.post("/api/org/role-assignments", json={"user_ref": email, "role": role}))
    client = TestClient(app)
    login_and_activate(client, email, password)
    return client


def integration(admin, name, scopes=SCOPES, environment="prod", capabilities=None):
    body = {
        "name": name,
        "namespace": name,
        "project": "documents",
        "environment": environment,
        "scopes": scopes,
        "capabilities": capabilities or [],
    }
    result = ok(admin.post("/api/portable/integrations", json=body))
    return result["integration"], {"Authorization": "Bearer " + result["token"]}


def decide(client, record, decision):
    return client.post(
        f"/api/portable/records/{record['record_id']}/{decision}",
        json={**RATIONALE, "expected_body_digest": record["body_digest"]},
    )


@pytest.fixture
def setup(super_admin_client):
    from app.main import app

    ok(
        super_admin_client.post(
            "/api/admin/organizations",
            json={
                "tenant_id": "documents",
                "name": "Documents",
                "admin_email": "admin@documents.test",
                "admin_display_name": "Admin",
                "admin_password": "admin-password-1234",
            },
        )
    )
    admin = TestClient(app)
    login_and_activate(admin, "admin@documents.test", "admin-password-1234")
    activator = user(admin, "activator@documents.test", "org_admin")
    builder = user(admin, "builder@documents.test", "governance_admin")
    reviewer = user(admin, "reviewer@documents.test", "governance_admin")
    executor, headers = integration(admin, "job-runner", capabilities=[CAPABILITY])
    collector, evidence_headers = integration(
        admin, "evidence-collector", scopes=["systems:read", "observations:write"]
    )
    system = ok(admin.post("/v1/portable/systems", headers=headers, json=SYSTEM))["system"]
    rule = {
        "models": MANIFEST["models"],
        "tools": MANIFEST["tools"],
        "resources": MANIFEST["resources"],
        "actions": ["disable-trigger"],
        "remediation_actions": ["disable-trigger"],
        "required_checks": ["quality"],
        "trusted_sources": [collector["record_id"]],
    }
    policy = ok(admin.post(f"/api/portable/systems/{system['record_id']}/policies", json=rule))["policy"]
    ok(decide(activator, policy, "activate_policy"))
    ok(decide(reviewer, system, "approve_system"))
    revision = ok(
        builder.post(
            "/api/portable/submissions",
            json={"integration_id": executor["record_id"], "system_id": system["record_id"], "manifest": MANIFEST},
        )
    )["revision"]
    state = dict(
        admin=admin,
        activator=activator,
        builder=builder,
        reviewer=reviewer,
        executor=executor,
        headers=headers,
        collector=collector,
        evidence_headers=evidence_headers,
        system=system,
        policy=policy,
        rule=rule,
        revision=revision,
    )
    try:
        yield state
    finally:
        for client in (admin, activator, builder, reviewer):
            client.close()


def observe(s, check="quality", result="passing", headers=None, **patch):
    timestamp = datetime.now(UTC).isoformat()
    payload = {
        "external_id": "obs-" + timestamp,
        "check_id": check,
        "result": result,
        "observed_at": timestamp,
        "revision_digest": s["revision"]["body"]["manifest_digest"],
        "evidence_ref": "urn:evidence:assessment",
        **patch,
    }
    return s["admin"].post(
        f"/v1/portable/systems/{s['system']['record_id']}/observations",
        headers=headers or s["evidence_headers"],
        json=payload,
    )


def authorize(s, purpose="release", **patch):
    payload = {"revision_id": s["revision"]["record_id"], "purpose": purpose, **patch}
    return s["admin"].post("/v1/portable/authorizations", headers=s["headers"], json=payload)


def ready(s):
    ok(observe(s))
    ok(decide(s["reviewer"], s["revision"], "approve_revision"))


def consume(s, grant, **patch):
    payload = {"token": grant["token"], "request": {**grant["authorization"]["body"]["request"], **patch}}
    return s["admin"].post("/v1/portable/authorizations/consume", headers=s["headers"], json=payload)


def test_stable_binding_rename_preserves_approval_and_purpose_change_invalidates(setup):
    s = setup
    renamed = ok(
        s["admin"].post("/v1/portable/systems", headers=s["headers"], json={**SYSTEM, "display_name": "Renamed"})
    )["system"]
    assert renamed["record_id"] == s["system"]["record_id"] and renamed["state"] == "approved"
    changed = ok(
        s["admin"].post("/v1/portable/systems", headers=s["headers"], json={**SYSTEM, "purpose": "Different purpose"})
    )["system"]
    assert changed["state"] == "planned"
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "requires_review"
    assert s["admin"].get("/api/portable/systems").json()["systems"][0]["record_id"] == renamed["record_id"]


def test_manifest_is_immutable_idempotent_and_rejects_spoofed_actor(setup):
    s = setup
    url = f"/v1/portable/systems/{s['system']['record_id']}/revisions"
    assert (
        ok(s["admin"].post(url, headers=s["headers"], json=MANIFEST))["revision"]["record_id"]
        == s["revision"]["record_id"]
    )
    assert s["admin"].post(url, headers=s["headers"], json={**MANIFEST, "tools": []}).status_code == 409
    assert (
        s["admin"]
        .post(url, headers=s["headers"], json={**MANIFEST, "submitted_by": "reviewer@documents.test"})
        .status_code
        == 422
    )
    assert s["revision"]["created_by"] == "builder@documents.test"


def test_existing_ingestion_key_is_not_integration_authority(setup):
    s = setup
    token = ok(s["admin"].post("/api/ingestion-keys", json={"name": "telemetry"}))["token"]
    assert (
        s["admin"].post("/v1/portable/systems", headers={"Authorization": "Bearer " + token}, json=SYSTEM).status_code
        == 401
    )
    assert s["admin"].post("/v1/portable/systems", headers=s["evidence_headers"], json=SYSTEM).status_code == 403
    assert (
        s["admin"]
        .post(
            "/api/portable/records/unknown/approve_system",
            headers=s["headers"],
            json={**RATIONALE, "expected_body_digest": "sha256:" + "0" * 64},
        )
        .status_code
        == 404
    )


def test_scope_separation_and_inactive_sources(setup):
    s = setup
    _, staging = integration(s["admin"], "staging-runner", environment="staging")
    assert s["admin"].get(f"/v1/portable/systems/{s['system']['record_id']}", headers=staging).status_code == 404
    ok(s["admin"].post(f"/api/portable/integrations/{s['collector']['record_id']}/revoke"))
    assert observe(s).status_code == 403
    assert "token" not in str(s["admin"].get("/api/portable/integrations").json())


def test_no_missing_stale_wrong_revision_or_untrusted_evidence_can_clear_release(setup):
    s = setup
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "indeterminate"
    ok(observe(s, headers=s["headers"]))
    ok(observe(s, revision_digest="sha256:" + "b" * 64))
    ok(observe(s, observed_at=(datetime.now(UTC) - timedelta(days=2)).isoformat()))
    assert ok(authorize(s))["token"] is None
    ok(observe(s))
    result = ok(authorize(s))
    assert result["authorization"]["body"]["outcome"] == "requires_review"
    assert decide(s["builder"], s["revision"], "approve_revision").status_code == 403
    ok(decide(s["reviewer"], s["revision"], "approve_revision"))
    grant = ok(authorize(s))
    assert grant["authorization"]["body"]["outcome"] == "allow"
    assert authorize(s).headers["cache-control"] == "no-store"
    ok(consume(s, grant))
    assert consume(s, grant).status_code == 409


def test_future_evidence_and_observation_overwrites_are_rejected(setup):
    s = setup
    assert observe(s, observed_at=(datetime.now(UTC) + timedelta(seconds=1)).isoformat()).status_code == 422
    result = ok(observe(s, external_id="stable"))["observation"]
    assert (
        observe(s, external_id="stable", observed_at=result["body"]["observed_at"], result="failed").status_code == 409
    )
    assert observe(s, observed_at="2026-01-01T00:00:00").status_code == 422


@pytest.mark.parametrize("change", ["evidence", "policy", "retire", "expiry", "plan"])
def test_outstanding_permit_rechecks_current_conditions(setup, change):
    s = setup
    ready(s)
    grant = ok(authorize(s))
    if change == "evidence":
        ok(observe(s, result="failed"))
    elif change == "policy":
        policy = ok(s["admin"].post(f"/api/portable/systems/{s['system']['record_id']}/policies", json=s["rule"]))[
            "policy"
        ]
        assert decide(s["admin"], policy, "activate_policy").status_code == 403
        ok(decide(s["activator"], policy, "activate_policy"))
    elif change == "retire":
        ok(decide(s["reviewer"], s["system"], "retire_system"))
    elif change == "expiry":
        from app.storage.portable import connect

        with connect() as connection:
            connection.execute(
                "UPDATE portable_credentials SET expires_at = ? WHERE record_id = ?",
                ("2000-01-01T00:00:00Z", grant["authorization"]["record_id"]),
            )
    else:
        assert (
            consume(
                s, grant, purpose="runtime", action={"capability": "disable-trigger", "resource_id": "record-store"}
            ).status_code
            == 409
        )
        return
    assert consume(s, grant).status_code == 409


def test_permit_consumption_is_atomic_under_concurrency(setup):
    s = setup
    ready(s)
    grant = ok(authorize(s))
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(lambda _: consume(s, grant).status_code, range(2)))
    assert sorted(codes) == [200, 409]


def test_routine_release_requires_explicit_independently_activated_policy(setup):
    s = setup
    ok(observe(s))
    policy = ok(
        s["admin"].post(
            f"/api/portable/systems/{s['system']['record_id']}/policies",
            json={**s["rule"], "allow_routine_releases": True},
        )
    )["policy"]
    ok(decide(s["activator"], policy, "activate_policy"))
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "allow"
    assert (
        s["admin"].get(f"/api/portable/systems/{s['system']['record_id']}").json()["revisions"][0]["state"]
        == "pending_review"
    )


@pytest.mark.parametrize(
    "field,value",
    [("models", ["unapproved/model"]), ("autonomy_level", 4), ("external_action", True), ("human_checkpoint", False)],
)
def test_manifest_boundary_changes_deny_release(setup, field, value):
    s = setup
    revised = ok(
        s["admin"].post(
            f"/v1/portable/systems/{s['system']['record_id']}/revisions",
            headers=s["headers"],
            json={**MANIFEST, "revision": "r2", field: value},
        )
    )["revision"]
    s["revision"] = revised
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "deny"


def test_remediation_does_not_require_the_failed_condition_to_pass_first(setup):
    s = setup
    ok(observe(s, result="failed"))
    action = {"capability": "disable-trigger", "resource_id": "record-store"}
    grant = ok(authorize(s, purpose="remediation", action=action))
    assert grant["authorization"]["body"]["outcome"] == "allow"
    assert ok(authorize(s, purpose="runtime", action=action))["token"] is None
    assert ok(authorize(s, purpose="remediation", action={**action, "resource_id": "other-store"}))["token"] is None
    assert ok(authorize(s, purpose="remediation", action={**action, "parameters": {"enable": True}}))["token"] is None
    ok(consume(s, grant))
    receipt = ok(
        s["admin"].post(
            "/v1/portable/receipts",
            headers=s["headers"],
            json={
                "authorization_id": grant["authorization"]["record_id"],
                "outcome": "executed",
                "evidence_ref": "urn:execution:disabled",
            },
        )
    )["receipt"]
    assert receipt["state"] == "verification_pending"
    url = f"/v1/portable/receipts/{receipt['record_id']}/verify"
    before = ok(observe(s, check="trigger-disabled"))["observation"]
    assert s["admin"].post(url, headers=s["headers"], json={"observation_id": before["record_id"]}).status_code == 403
    assert (
        s["admin"].post(url, headers=s["evidence_headers"], json={"observation_id": before["record_id"]}).status_code
        == 409
    )
    proof = ok(
        observe(
            s,
            check="trigger-disabled",
            action_digest=grant["authorization"]["body"]["request_digest"],
            resource_id="record-store",
        )
    )["observation"]
    assert (
        ok(s["admin"].post(url, headers=s["evidence_headers"], json={"observation_id": proof["record_id"]}))["receipt"][
            "state"
        ]
        == "verified"
    )
    assert (
        s["admin"].post(url, headers=s["evidence_headers"], json={"observation_id": proof["record_id"]}).status_code
        == 409
    )


def test_receipts_cannot_precede_execution_or_change_outcome(setup):
    s = setup
    grant = ok(
        authorize(s, purpose="remediation", action={"capability": "disable-trigger", "resource_id": "record-store"})
    )
    payload = {
        "authorization_id": grant["authorization"]["record_id"],
        "outcome": "failed",
        "evidence_ref": "urn:execution:failure",
    }
    assert s["admin"].post("/v1/portable/receipts", headers=s["headers"], json=payload).status_code == 409
    ok(consume(s, grant))
    receipt = ok(s["admin"].post("/v1/portable/receipts", headers=s["headers"], json=payload))["receipt"]
    assert receipt["state"] == "failed"
    assert (
        s["admin"]
        .post("/v1/portable/receipts", headers=s["headers"], json={**payload, "outcome": "executed"})
        .status_code
        == 409
    )


def test_delegation_is_exact_single_use_and_rechecks_human_permission(setup):
    s = setup
    ready(s)
    new = ok(
        s["admin"].post(
            f"/v1/portable/systems/{s['system']['record_id']}/revisions",
            headers=s["headers"],
            json={**MANIFEST, "revision": "r2"},
        )
    )["revision"]
    s["revision"] = new
    ok(observe(s))
    payload = {
        **RATIONALE,
        "integration_id": s["executor"]["record_id"],
        "target_id": new["record_id"],
        "expected_body_digest": new["body_digest"],
        "decision": "approve_revision",
    }
    delegated = ok(s["reviewer"].post("/api/portable/delegations", json=payload))
    assert (
        ok(s["admin"].get(f"/api/portable/systems/{s['system']['record_id']}"))["revisions"][0]["state"]
        == "pending_review"
    )
    result = ok(
        s["admin"].post("/v1/portable/delegations/redeem", headers=s["headers"], json={"token": delegated["token"]})
    )
    assert result["record"]["state"] == "approved"
    assert (
        s["admin"]
        .post("/v1/portable/delegations/redeem", headers=s["headers"], json={"token": delegated["token"]})
        .status_code
        == 409
    )
    another = ok(
        s["admin"].post(
            f"/v1/portable/systems/{s['system']['record_id']}/revisions",
            headers=s["headers"],
            json={**MANIFEST, "revision": "r3"},
        )
    )["revision"]
    s["revision"] = another
    ok(observe(s))
    delegated = ok(
        s["reviewer"].post(
            "/api/portable/delegations",
            json={**payload, "target_id": another["record_id"], "expected_body_digest": another["body_digest"]},
        )
    )
    ok(
        s["admin"].post(
            "/api/org/role-assignments",
            json={"user_ref": "reviewer@documents.test", "role": "governance_admin", "status": "revoked"},
        )
    )
    assert (
        s["admin"]
        .post("/v1/portable/delegations/redeem", headers=s["headers"], json={"token": delegated["token"]})
        .status_code
        == 403
    )


def test_control_pack_is_versioned_scoped_and_does_not_claim_whole_framework(setup):
    s = setup
    pack = {
        "pack_id": "execution-basics",
        "version": "1",
        "trusted_sources": [s["collector"]["record_id"]],
        "controls": [
            {
                "control_id": "QUALITY",
                "name": "Quality assessed",
                "resource_types": ["job"],
                "check_ids": ["quality"],
                "framework_refs": ["example-framework-v1 requirement-1"],
            },
            {
                "control_id": "OTHER",
                "name": "Other type",
                "resource_types": ["web-service"],
                "check_ids": ["quality"],
                "framework_refs": ["example-framework-v1 requirement-2"],
            },
        ],
    }
    url = "/api/portable/control-packs?project=documents&environment=prod"
    record = ok(s["admin"].post(url, json=pack))["pack"]
    assert decide(s["admin"], record, "activate_pack").status_code == 403
    ok(decide(s["activator"], record, "activate_pack"))
    assert s["admin"].post(url, json={**pack, "controls": []}).status_code == 422
    assert s["admin"].post(url, json={**pack, "trusted_sources": [s["executor"]["record_id"]]}).status_code == 409
    controls_url = f"/api/portable/systems/{s['system']['record_id']}/controls?revision_id={s['revision']['record_id']}"
    before = ok(s["admin"].get(controls_url))
    assert [c["status"] for c in before["assessments"]] == ["unknown", "not_applicable"]
    ok(observe(s))
    after = ok(s["admin"].get(controls_url))
    assert after["assessments"][0]["status"] == "passing"
    assert "not certification" in after["basis"]
    ok(observe(s, result="failed"))
    assert ok(s["admin"].get(controls_url))["assessments"][0]["status"] == "failed"


def test_offboarding_purges_portable_data_and_credentials(setup):
    s = setup
    from app.storage.retention import purge_tenant_data

    counts = purge_tenant_data("documents")
    assert counts["portable_records"] > 0 and counts["portable_credentials"] > 0
    assert s["admin"].get(f"/v1/portable/systems/{s['system']['record_id']}", headers=s["headers"]).status_code == 401


def test_routine_runtime_needs_successful_release_receipt_and_current_policy(setup):
    s = setup
    ok(observe(s))
    policy = ok(
        s["admin"].post(
            f"/api/portable/systems/{s['system']['record_id']}/policies",
            json={**s["rule"], "allow_routine_releases": True},
        )
    )["policy"]
    ok(decide(s["activator"], policy, "activate_policy"))
    action = {"capability": "disable-trigger", "resource_id": "record-store"}
    assert ok(authorize(s, purpose="runtime", action=action))["authorization"]["body"]["outcome"] == "requires_review"
    release = ok(authorize(s))
    ok(consume(s, release))
    result = ok(
        s["admin"].post(
            "/v1/portable/receipts",
            headers=s["headers"],
            json={
                "authorization_id": release["authorization"]["record_id"],
                "outcome": "executed",
                "evidence_ref": "urn:job:published",
            },
        )
    )["receipt"]
    assert result["state"] == "reported_executed"
    assert ok(authorize(s, purpose="runtime", action=action))["authorization"]["body"]["outcome"] == "allow"
    detail = ok(s["admin"].get(f"/api/portable/systems/{s['system']['record_id']}"))
    assert detail["revisions"][0]["state"] == "pending_review"
    assert detail["active_policy"]["record_id"] == policy["record_id"]
    # Replacement policy cannot silently inherit the earlier policy's deployment.
    new = ok(
        s["admin"].post(
            f"/api/portable/systems/{s['system']['record_id']}/policies",
            json={**s["rule"], "allow_routine_releases": True},
        )
    )["policy"]
    ok(decide(s["activator"], new, "activate_policy"))
    assert ok(authorize(s, purpose="runtime", action=action))["authorization"]["body"]["outcome"] == "requires_review"


def test_indexed_evidence_is_not_limited_to_the_latest_500_records(setup):
    s = setup
    from app.storage import portable as store

    with store.transaction("documents") as connection:
        for index in range(510):
            store.insert(
                connection,
                tenant_id="documents",
                kind="observation",
                project="documents",
                environment="prod",
                integration_id=s["collector"]["record_id"],
                external_id=f"old-{index}",
                state="recorded",
                created_by="integration:" + s["collector"]["record_id"],
                body={
                    "system_id": s["system"]["record_id"],
                    "revision_digest": "sha256:" + "f" * 64,
                    "check_id": "quality",
                    "observed_at": "2000-01-01T00:00:00Z",
                    "result": "passing",
                },
            )
    ok(observe(s))
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "requires_review"
    ok(observe(s, result="failed"))
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "deny"


def test_other_tenant_cannot_read_authorize_or_decide_system(setup, super_admin_client):
    s = setup
    from app.main import app

    ok(
        super_admin_client.post(
            "/api/admin/organizations",
            json={
                "tenant_id": "other",
                "name": "Other",
                "admin_email": "admin@other.test",
                "admin_display_name": "Other",
                "admin_password": "admin-password-1234",
            },
        )
    )
    other = TestClient(app)
    login_and_activate(other, "admin@other.test", "admin-password-1234")
    _, headers = integration(other, "other-runner")
    assert other.get(f"/api/portable/systems/{s['system']['record_id']}").status_code == 404
    assert other.get(f"/v1/portable/systems/{s['system']['record_id']}", headers=headers).status_code == 404
    assert (
        other.post(
            "/v1/portable/authorizations",
            headers=headers,
            json={"revision_id": s["revision"]["record_id"], "purpose": "release"},
        ).status_code
        == 404
    )
    assert decide(other, s["system"], "approve_system").status_code == 404
    other.close()


def test_public_contract_can_be_consumed_by_the_independent_python_client(setup):
    s = setup
    from norinth_logger.portable import PermissionDenied, PortableClient, PortableError

    def transport(path, payload):
        response = (
            s["admin"].get(path, headers=s["headers"])
            if payload is None
            else s["admin"].post(path, headers=s["headers"], json=payload)
        )
        if response.status_code != 200:
            raise PortableError("Request rejected")
        return response.json()

    runner = PortableClient("https://norinth.example.test", "nri_example", transport=transport)
    assert runner.workspace(s["system"]["record_id"])["system"]["record_id"] == s["system"]["record_id"]
    assert runner.controls(s["system"]["record_id"], s["revision"]["record_id"])["assessments"] == []
    request = {"revision_id": s["revision"]["record_id"], "purpose": "release"}
    with pytest.raises(PermissionDenied):
        runner.consume(runner.authorize(request), request)
    ready(s)
    grant = runner.authorize(request)
    consumed = runner.consume(grant, request)
    assert consumed["state"] == "consumed"
    with pytest.raises(PortableError):
        runner.consume(grant, request)
    receipt = runner.receipt(consumed["record_id"], outcome="executed", evidence_ref="urn:runner:job-42")
    assert receipt["state"] == "reported_executed"


def test_portable_client_does_not_fail_open_or_follow_redirects():
    import urllib.error

    from norinth_logger.portable import PortableClient, PortableError, _NoRedirect

    with pytest.raises(ValueError):
        PortableClient("http://example.test", "nri_example")
    with pytest.raises(ValueError):
        PortableClient("https://example.test", "nrk_telemetry")
    assert _NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.test") is None

    def unavailable(path, payload):
        raise urllib.error.URLError("offline")

    client = PortableClient("https://example.test", "nri_example", transport=unavailable)
    with pytest.raises(PortableError):
        client.authorize({"revision_id": "r1", "purpose": "release"})
    with pytest.raises(PortableError):
        client.consume({"authorization": {"record_id": "a1", "body": {"outcome": "allow"}}, "token": None}, {})


def test_out_of_order_or_equal_time_failure_cannot_be_overwritten_by_pass(setup):
    s = setup
    timestamp = datetime.now(UTC).isoformat()
    ok(observe(s, external_id="failed-1", result="failed", observed_at=timestamp))
    ok(observe(s, external_id="pass-1", observed_at=timestamp))
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "deny"
    ok(observe(s, external_id="old-pass", observed_at="2000-01-01T00:00:00Z"))
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "deny"


def test_unknown_evidence_remains_indeterminate_and_missing_source_does_not_pass(setup):
    s = setup
    ok(observe(s, result="unknown"))
    current = ok(authorize(s))["authorization"]["body"]
    assert current["outcome"] == "indeterminate" and current["reasons"] == ["unknown_evidence:quality"]
    ok(observe(s))
    ok(s["admin"].post(f"/api/portable/integrations/{s['collector']['record_id']}/revoke", json={}))
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "indeterminate"


def test_machine_token_alone_cannot_issue_a_human_decision(setup):
    s = setup
    from app.main import app

    machine = TestClient(app)
    assert (
        machine.post(
            f"/api/portable/records/{s['revision']['record_id']}/approve_revision", headers=s["headers"], json=RATIONALE
        ).status_code
        == 401
    )
    machine.close()


def test_integration_pagination_and_machine_revocation_under_lock(setup):
    s = setup
    first = ok(s["admin"].get("/api/portable/integrations?limit=1"))
    second = ok(s["admin"].get("/api/portable/integrations?limit=1&offset=1"))
    assert first["has_more"] and first["integrations"][0]["record_id"] != second["integrations"][0]["record_id"]
    from app.api.portable import source_transaction
    from app.storage import portable as store
    from fastapi import HTTPException

    with store.connect() as connection:
        stale = store.load(connection, "documents", s["executor"]["record_id"])
    ok(s["admin"].post(f"/api/portable/integrations/{stale['record_id']}/revoke", json={}))
    with pytest.raises(HTTPException) as error, source_transaction(stale):
        pass
    assert error.value.status_code == 403


def test_audit_failure_cannot_confer_authority_and_retry_preserves_original_decider(setup, monkeypatch):
    s = setup
    from app.api import portable as api
    from app.main import app
    from app.storage import portable as store
    from app.storage.audit import record_audit as real_audit

    ok(observe(s))

    def unavailable(**kwargs):
        raise RuntimeError("Audit storage unavailable")

    monkeypatch.setattr(api, "record_audit", unavailable)
    # A transport error after the DB write never turns into an allowed release.
    with TestClient(app, raise_server_exceptions=False) as failed:
        failed.cookies.update(s["reviewer"].cookies)
        response = decide(failed, s["revision"], "approve_revision")
        assert response.status_code == 500
    monkeypatch.setattr(api, "record_audit", real_audit)
    result = ok(authorize(s))["authorization"]["body"]
    assert result["outcome"] == "indeterminate" and result["reasons"] == ["governance_audit_pending"]
    recovered = ok(s["reviewer"].post(f"/api/portable/records/{s['revision']['record_id']}/audit/retry", json={}))
    assert recovered["record"]["state"] == "approved" and recovered["record"]["audited_at"]
    with store.connect() as connection:
        decision = store.load(connection, "documents", recovered["record"]["decision_id"], "decision")
    assert decision["created_by"] == "reviewer@documents.test"
    assert decision["body"]["rationale"] == RATIONALE["rationale"]
    assert decision["body"]["target_snapshot"] == s["revision"]["body"]
    assert ok(authorize(s))["authorization"]["body"]["outcome"] == "allow"


def test_credential_rotation_preserves_binding_and_does_not_revive_revoked_integration(setup):
    s = setup
    url = f"/api/portable/integrations/{s['executor']['record_id']}"
    rotated = ok(s["admin"].post(url + "/rotate", json={}))
    assert rotated["integration"]["record_id"] == s["executor"]["record_id"]
    assert s["admin"].get(f"/v1/portable/systems/{s['system']['record_id']}", headers=s["headers"]).status_code == 401
    headers = {"Authorization": "Bearer " + rotated["token"]}
    bound = ok(s["admin"].post("/v1/portable/systems", headers=headers, json=SYSTEM))["system"]
    assert bound["record_id"] == s["system"]["record_id"] and bound["state"] == "approved"
    ok(s["admin"].post(url + "/revoke", json={}))
    assert s["admin"].post(url + "/rotate", json={}).status_code == 409


def test_server_adapter_can_read_current_workspace_without_issuing_permits(setup):
    s = setup
    ready(s)
    from app.storage import portable as store

    with store.connect() as connection:
        before = len(store.records(connection, "documents", "authorization"))
    workspace = ok(
        s["admin"].get(f"/v1/portable/systems/{s['system']['record_id']}/workspace", headers=s["evidence_headers"])
    )
    assert workspace["eligibility"][s["revision"]["record_id"]]["outcome"] == "allow"
    assert "token" not in str(workspace)
    assert workspace["active_policy"]["record_id"] == s["policy"]["record_id"]
    controls = ok(
        s["admin"].get(
            f"/v1/portable/systems/{s['system']['record_id']}/controls?revision_id={s['revision']['record_id']}",
            headers=s["evidence_headers"],
        )
    )
    assert controls["assessments"] == []
    with store.connect() as connection:
        assert len(store.records(connection, "documents", "authorization")) == before


def test_human_approval_rejects_a_system_changed_after_review(setup):
    s = setup
    original = ok(
        s["admin"].post("/v1/portable/systems", headers=s["headers"], json={**SYSTEM, "external_id": "job-43"})
    )["system"]
    changed = ok(
        s["admin"].post(
            "/v1/portable/systems",
            headers=s["headers"],
            json={**SYSTEM, "external_id": "job-43", "purpose": "A different operating purpose"},
        )
    )["system"]
    assert changed["record_id"] == original["record_id"] and changed["body_digest"] != original["body_digest"]
    assert decide(s["reviewer"], original, "approve_system").status_code == 409
    assert ok(s["admin"].get(f"/api/portable/systems/{changed['record_id']}"))["system"]["state"] == "planned"
    assert ok(decide(s["reviewer"], changed, "approve_system"))["record"]["state"] == "approved"


def test_delegated_approval_is_bound_to_the_exact_reviewed_system_body(setup):
    s = setup
    original = ok(
        s["admin"].post("/v1/portable/systems", headers=s["headers"], json={**SYSTEM, "external_id": "job-43"})
    )["system"]
    token = ok(
        s["reviewer"].post(
            "/api/portable/delegations",
            json={
                **RATIONALE,
                "expected_body_digest": original["body_digest"],
                "integration_id": s["executor"]["record_id"],
                "target_id": original["record_id"],
                "decision": "approve_system",
            },
        )
    )["token"]
    changed = ok(
        s["admin"].post(
            "/v1/portable/systems",
            headers=s["headers"],
            json={**SYSTEM, "external_id": "job-43", "purpose": "An unreviewed purpose"},
        )
    )["system"]
    response = s["admin"].post("/v1/portable/delegations/redeem", headers=s["headers"], json={"token": token})
    assert response.status_code == 409
    assert ok(s["admin"].get(f"/api/portable/systems/{changed['record_id']}"))["system"]["state"] == "planned"


def test_new_decision_contract_does_not_allow_unbound_approval(setup):
    s = setup
    assert (
        s["reviewer"]
        .post(f"/api/portable/records/{s['revision']['record_id']}/approve_revision", json=RATIONALE)
        .status_code
        == 422
    )


def test_readonly_eligibility_cannot_report_allow_for_an_unaudited_executor(setup):
    s = setup
    ready(s)
    from app.storage import portable as store

    with store.connect() as connection:
        connection.execute(
            "UPDATE portable_records SET audited_at = '' WHERE record_id = ?", (s["executor"]["record_id"],)
        )
    snapshot = ok(s["admin"].get(f"/api/portable/systems/{s['system']['record_id']}"))
    current = snapshot["eligibility"][s["revision"]["record_id"]]
    assert current["outcome"] == "indeterminate" and current["reasons"] == ["executor_audit_pending"]

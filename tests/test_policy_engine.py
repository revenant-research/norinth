"""governance policy engine: storage, validation, activation, and the seeded default

the platform default (tenant_id '') must encode pre-policy behavior exactly:
an install that never authors a policy behaves as it did before the engine
existed. these tests pin that equivalence and the write-path rules
"""

from __future__ import annotations

import pathlib
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _make_org(super_admin_client, tenant_id="acme"):
    resp = super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant_id,
            "name": tenant_id,
            "admin_email": f"admin@{tenant_id}.test",
            "admin_display_name": f"{tenant_id} admin",
            "admin_password": f"{tenant_id}-admin-pw-1",
        },
    )
    assert resp.status_code == 200, resp.text
    return f"admin@{tenant_id}.test", f"{tenant_id}-admin-pw-1"


def _client_for(email, password):
    """sign in, handling the first-login rotation on repeat sign-ins"""
    from app.main import app

    client = TestClient(app)
    login = client.post("/api/auth/login", json={"email": email, "password": password})
    if login.status_code != 200:
        login_and_activate(client, email, f"{password}-rotated-1")
        return client
    if login.json()["user"].get("must_change_password"):
        changed = client.post(
            "/api/auth/change-password",
            json={"current_password": password, "new_password": f"{password}-rotated-1"},
        )
        assert changed.status_code == 200, changed.text
    return client


def _add_user(org_client, email, role=None, password=None):
    password = password or "user-pw-123456"
    resp = org_client.post("/api/org/users", json={"email": email, "display_name": email.split("@")[0], "password": password})
    assert resp.status_code == 200, resp.text
    if role:
        granted = org_client.post("/api/org/role-assignments", json={"user_ref": email, "role": role})
        assert granted.status_code == 200, granted.text
    return email, password


def _two_stage_policy(extra=None):
    body = {
        "schema": "governance-policy/v1",
        "intake": {
            "tiers": {
                "high": {
                    "stages": [
                        {"role": "governance_reviewer", "label": "Security review"},
                        {"role": "risk_owner", "label": "Risk acceptance"},
                    ],
                    "mode": "sequence",
                }
            }
        },
    }
    if extra:
        body.update(extra)
    return body


def test_platform_default_policy_is_seeded_and_active(fresh_db):
    from app.storage.policy_engine import DEFAULT_POLICY_BODY, body_hash, effective_policy

    policy = effective_policy(None)
    assert policy["tenant_id"] == ""
    assert policy["version"] == 1
    assert policy["source"] == "default"
    assert policy["body"] == DEFAULT_POLICY_BODY
    assert policy["body_hash"] == body_hash(DEFAULT_POLICY_BODY)
    # a tenant with no policy of its own is governed by the platform default
    assert effective_policy("acme")["tenant_id"] == ""


def test_validation_rejects_malformed_documents(fresh_db):
    from app.storage.policy_engine import validate_policy_body

    def errors_of(body):
        return validate_policy_body(body)

    assert errors_of("not an object") == ["policy body must be a JSON object"]
    assert any("schema" in e for e in errors_of({"schema": "governance-policy/v9"}))
    assert any("unknown top-level" in e for e in errors_of({"schema": "governance-policy/v1", "webhooks": {}}))
    # unknown tier names, empty stages, unknown stage keys
    assert any("unknown risk tier" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"critical": {"stages": [{"role": "governance_reviewer"}]}}}}))
    assert any("non-empty" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": []}}}}))
    assert any("unknown keys" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": [{"role": "governance_reviewer", "webhook": "x"}]}}}}))
    # roles must exist and hold review.decide
    assert any("does not exist" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": [{"role": "wizard"}]}}}}))
    assert any("review.decide" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": [{"role": "org_admin"}]}}}}))
    # mode and recertification floor
    assert any("mode" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": [{"role": "governance_reviewer"}], "mode": "vote"}}}}))
    assert any("recertify_days" in e for e in errors_of({"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": [{"role": "governance_reviewer"}], "recertify_days": 5}}}}))
    # gates can only tighten: the material-change ceiling is the shipped floor
    assert any("cannot exceed" in e for e in errors_of({"schema": "governance-policy/v1", "gates": {"environments": {"production": {"max_open_material_changes": 3}}}}))
    # field keys are identifier-shaped, unique, capped
    bad_fields = {"schema": "governance-policy/v1", "intake": {"fields": [{"key": "Bad Key!"}]}}
    assert any("key must match" in e for e in errors_of(bad_fields))
    dupes = {"schema": "governance-policy/v1", "intake": {"fields": [{"key": "dpia_ref"}, {"key": "dpia_ref"}]}}
    assert any("duplicate key" in e for e in errors_of(dupes))


def test_default_policy_document_is_valid(fresh_db):
    from app.storage.policy_engine import DEFAULT_POLICY_BODY, validate_policy_body

    assert validate_policy_body(DEFAULT_POLICY_BODY) == []


def test_draft_activate_supersede_and_audit_chain(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        # drafting an invalid document is refused with the validation errors
        invalid = org.post("/api/governance-policy/draft", json={"body": {"schema": "nope"}})
        assert invalid.status_code == 400
        assert "schema" in invalid.json()["detail"]

        draft = org.post("/api/governance-policy/draft", json={"body": _two_stage_policy()})
        assert draft.status_code == 200, draft.text
        version = draft.json()["policy"]["version"]
        assert draft.json()["policy"]["status"] == "draft"

        # the draft is not in force until activated
        assert org.get("/api/governance-policy").json()["policy"]["source"] == "default"

        activated = org.post(f"/api/governance-policy/versions/{version}/activate")
        assert activated.status_code == 200, activated.text
        assert activated.json()["policy"]["status"] == "active"
        in_force = org.get("/api/governance-policy").json()["policy"]
        assert in_force["source"] == "tenant" and in_force["version"] == version

        # activating a second version supersedes the first in the same step
        second = org.post("/api/governance-policy/draft", json={"body": _two_stage_policy({"vendors": {"stages": [{"role": "governance_reviewer"}], "recertify_days": 180}})})
        v2 = second.json()["policy"]["version"]
        assert org.post(f"/api/governance-policy/versions/{v2}/activate").status_code == 200
        versions = {row["version"]: row["status"] for row in org.get("/api/governance-policy/versions").json()["versions"]}
        assert versions[version] == "superseded" and versions[v2] == "active"

        # a superseded version can never come back; forward-only history
        stale = org.post(f"/api/governance-policy/versions/{version}/activate")
        assert stale.status_code == 400
        assert "superseded" in stale.json()["detail"]

        # every activation is in the audit chain with the body hash
        entries = org.get("/api/audit-logs?action=policy.activate").json()["audit_logs"]
        assert len(entries) == 2
        assert all(e["target_type"] == "governance_policy" for e in entries)
        assert "body_hash" in (entries[0]["detail"] or "")

        from app.storage.audit import verify_audit_chain

        assert verify_audit_chain()["ok"] is True


def test_policy_writes_require_config_write(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        _add_user(org, "viewer@acme.test", role="governance_viewer")
    with _client_for("viewer@acme.test", "user-pw-123456") as viewer:
        # every member can read the policy that governs them
        assert viewer.get("/api/governance-policy").status_code == 200
        # but only config.write holders can author or activate one
        assert viewer.post("/api/governance-policy/draft", json={"body": _two_stage_policy()}).status_code == 403
        assert viewer.get("/api/governance-policy/versions").status_code == 403
        assert viewer.post("/api/governance-policy/versions/1/activate").status_code == 403


def test_policy_versions_are_tenant_isolated(super_admin_client):
    email_a, password_a = _make_org(super_admin_client, "acme")
    email_b, password_b = _make_org(super_admin_client, "umbra")
    with _client_for(email_a, password_a) as acme:
        draft = acme.post("/api/governance-policy/draft", json={"body": _two_stage_policy()})
        version = draft.json()["policy"]["version"]
        assert acme.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200
    with _client_for(email_b, password_b) as umbra:
        # umbra sees no acme versions and stays governed by the platform default
        assert umbra.get("/api/governance-policy/versions").json()["versions"] == []
        assert umbra.get("/api/governance-policy").json()["policy"]["source"] == "default"


def test_diff_endpoint_names_what_changes(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        draft = org.post("/api/governance-policy/draft", json={"body": _two_stage_policy()})
        version = draft.json()["policy"]["version"]
        diff = org.get(f"/api/governance-policy/diff?to_version={version}")
        assert diff.status_code == 200, diff.text
        lines = " ".join(diff.json()["diff"])
        # the high tier gains a second stage relative to the default in force
        assert "intake.tiers.high.stages" in lines


def test_default_policy_behaves_exactly_like_the_old_workflow(super_admin_client):
    """equivalence pin: under the seeded default, intake produces one task,
    any review-decide holder decides it via /api/decisions, and the use case
    moves exactly as before the policy engine existed"""
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
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
        assert submitted.status_code == 200, submitted.text
        tasks = [t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "intake_review"]
        assert len(tasks) == 1
        task = tasks[0]
        # exactly one stage, pinned to the platform default policy, already open
        stages = org.get("/api/approval-stages").json()["approval_stages"]
        assert len(stages) == 1
        assert stages[0]["policy_tenant"] == "" and stages[0]["policy_version"] == 1
        assert stages[0]["status"] == "open"

        # a governance_admin (not governance_reviewer) can still decide, as before:
        # its authority covers the reviewer stage
        _add_user(org, "ga@acme.test", role="governance_admin", password="ga-pw-123456")
    with _client_for("ga@acme.test", "ga-pw-123456") as admin:
        decided = admin.post(
            "/api/decisions",
            json={
                "target_type": "review_task",
                "target_id": task["task_id"],
                "decision": "approve",
                "rationale": "Intake evidence reviewed; risk tier appropriate.",
            },
        )
        assert decided.status_code == 200, decided.text
        # the decision row is on the review task, exactly the pre-policy wire shape
        assert decided.json()["decision"]["target_type"] == "review_task"
    with _client_for(email, password) as org:
        record = next(r for r in org.get("/api/intake").json()["intake"] if r["application_name"] == "Claims")
        assert record["status"] == "approved"
        # the single stage was stamped with the decision so the packet can show
        # who decided which stage under which policy
        stage = org.get("/api/approval-stages").json()["approval_stages"][0]
        assert stage["status"] == "approved"
        assert stage["decided_by"] == "ga@acme.test"
        assert stage["decision_id"]

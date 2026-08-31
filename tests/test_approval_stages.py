"""multi-stage approvals: ordering, cross-stage segregation of duties, roll-up,
rejection, and policy-version pinning of in-flight work"""

from __future__ import annotations

import pathlib
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

HIGH_TIER_INTAKE = {
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

RATIONALE = "Evidence reviewed against the policy stage requirements."


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


def _add_user(org_client, email, role, password="user-pw-123456"):
    resp = org_client.post("/api/org/users", json={"email": email, "display_name": email.split("@")[0], "password": password})
    assert resp.status_code == 200, resp.text
    granted = org_client.post("/api/org/role-assignments", json={"user_ref": email, "role": role})
    assert granted.status_code == 200, granted.text
    return email, password


def _activate_policy(org_client, body):
    draft = org_client.post("/api/governance-policy/draft", json={"body": body})
    assert draft.status_code == 200, draft.text
    version = draft.json()["policy"]["version"]
    activated = org_client.post(f"/api/governance-policy/versions/{version}/activate")
    assert activated.status_code == 200, activated.text
    return version


def _two_stage_body(mode="sequence"):
    return {
        "schema": "governance-policy/v1",
        "intake": {
            "tiers": {
                "high": {
                    "stages": [
                        {"role": "governance_reviewer", "label": "Security review"},
                        {"role": "risk_owner", "label": "Risk acceptance"},
                    ],
                    "mode": mode,
                }
            }
        },
    }


def _submit_and_stages(org_client, payload=None):
    submitted = org_client.post("/api/intake", json=payload or HIGH_TIER_INTAKE)
    assert submitted.status_code == 200, submitted.text
    task = next(t for t in org_client.get("/api/review-tasks").json()["review_tasks"] if t["task_type"] == "intake_review")
    stages = org_client.get(f"/api/approval-stages?subject_type=review_task&subject_id={task['task_id']}").json()["approval_stages"]
    return task, sorted(stages, key=lambda s: s["stage_index"])


def _decide(client, stage_id, decision="approve"):
    return client.post(f"/api/approval-stages/{stage_id}/decide", json={"decision": decision, "rationale": RATIONALE})


def test_sequence_ordering_sod_and_roll_up(super_admin_client):
    email, password = _make_org(super_admin_client)
    with _client_for(email, password) as org:
        version = _activate_policy(org, _two_stage_body())
        # a governance_admin decides stage 0: its authority covers the
        # reviewer stage, and holding risk_owner authority too lets the test
        # prove the distinct-decider rule (not the role check) blocks stage 1
        _add_user(org, "reviewer@acme.test", "governance_admin")
        _add_user(org, "riskowner@acme.test", "risk_owner")
        _add_user(org, "submitter@acme.test", "governance_admin", password="sub-pw-123456")
    with _client_for("submitter@acme.test", "sub-pw-123456") as submitter:
        task, stages = _submit_and_stages(submitter)
    assert [s["status"] for s in stages] == ["open", "pending"]
    assert [s["required_role"] for s in stages] == ["governance_reviewer", "risk_owner"]
    assert [s["label"] for s in stages] == ["Security review", "Risk acceptance"]
    assert all(s["policy_version"] == version and s["policy_tenant"] == "acme" for s in stages)

    with _client_for(email, password) as org:
        # the queue routes the task to the open stage's role, not the default
        routed = next(t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_id"] == task["task_id"])
        assert routed["assigned_role"] == "governance_reviewer"

    # a multi-stage task refuses the direct decision route with directions
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        direct = reviewer.post(
            "/api/decisions",
            json={"target_type": "review_task", "target_id": task["task_id"], "decision": "approve", "rationale": RATIONALE},
        )
        assert direct.status_code == 400
        assert "multi-stage" in direct.json()["detail"]

        # stage 1 cannot be decided before stage 0 (sequence)
        premature = _decide(reviewer, stages[1]["stage_id"])
        assert premature.status_code == 409
        assert "not open yet" in premature.json()["detail"]

        # the submitter never decides their own work
    with _client_for("submitter@acme.test", "sub-pw-123456") as submitter:
        blocked = _decide(submitter, stages[0]["stage_id"])
        assert blocked.status_code == 403
        assert "Segregation of duties" in blocked.json()["detail"]

    # a bare reviewer lacks the authority of the risk_owner stage
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        first = _decide(reviewer, stages[0]["stage_id"])
        assert first.status_code == 200, first.text
        assert first.json()["stage"]["status"] == "approved"
        refreshed = {s["stage_index"]: s for s in first.json()["stages"]}
        assert refreshed[1]["status"] == "open"
        assert first.json()["subject_status"] == "open"

        # the same person cannot decide a second stage of the same subject
        second_by_same = _decide(reviewer, stages[1]["stage_id"])
        assert second_by_same.status_code == 403
        assert "different person" in second_by_same.json()["detail"]

    with _client_for(email, password) as org:
        routed = next(t for t in org.get("/api/review-tasks").json()["review_tasks"] if t["task_id"] == task["task_id"])
        assert routed["assigned_role"] == "risk_owner"

    with _client_for("riskowner@acme.test", "user-pw-123456") as riskowner:
        final = _decide(riskowner, stages[1]["stage_id"])
        assert final.status_code == 200, final.text
        assert final.json()["subject_status"] == "approved"
        # every stage decision is an append-only governance decision
        assert final.json()["decision"]["target_type"] == "approval_stage"

    with _client_for(email, password) as org:
        record = next(r for r in org.get("/api/intake").json()["intake"] if r["application_name"] == "Claims")
        assert record["status"] == "approved"
        decisions = org.get("/api/decisions").json()["decisions"]
        stage_decisions = [d for d in decisions if d["target_type"] == "approval_stage"]
        assert len(stage_decisions) == 2
        assert {d["actor_ref"] for d in stage_decisions} == {"reviewer@acme.test", "riskowner@acme.test"}

        # the roll-up closes the loop: the submitter is told the final outcome,
        # exactly once, only when the last stage lands
        outbox = org.get("/api/org/notifications").json()["notifications"]
        decided_notes = [n for n in outbox if n["event_type"] == "review.approved"]
        assert len(decided_notes) == 1
        assert decided_notes[0]["target"] == "submitter@acme.test"

        # a decided stage is terminal
    with _client_for("riskowner@acme.test", "user-pw-123456") as riskowner:
        again = _decide(riskowner, stages[1]["stage_id"], "reject")
        assert again.status_code == 409


def test_rejection_at_any_stage_rejects_the_subject(super_admin_client):
    email, password = _make_org(super_admin_client)
    with _client_for(email, password) as org:
        _activate_policy(org, _two_stage_body())
        _add_user(org, "reviewer@acme.test", "governance_reviewer")
        _add_user(org, "riskowner@acme.test", "risk_owner")
        task, stages = _submit_and_stages(org)
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        rejected = _decide(reviewer, stages[0]["stage_id"], "reject")
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["subject_status"] == "rejected"
    with _client_for(email, password) as org:
        record = next(r for r in org.get("/api/intake").json()["intake"] if r["application_name"] == "Claims")
        assert record["status"] == "rejected"
        stages_after = org.get(f"/api/approval-stages?subject_type=review_task&subject_id={task['task_id']}").json()["approval_stages"]
        by_index = {s["stage_index"]: s for s in stages_after}
        assert by_index[0]["status"] == "rejected"
        # the never-reached stage stays pending as a record; deciding it is refused
        assert by_index[1]["status"] == "pending"
        # the submitter hears the rejection
        outbox = org.get("/api/org/notifications").json()["notifications"]
        assert any(n["event_type"] == "review.rejected" for n in outbox)
    with _client_for("riskowner@acme.test", "user-pw-123456") as riskowner:
        late = _decide(riskowner, by_index[1]["stage_id"])
        assert late.status_code == 409
        assert "already been decided" in late.json()["detail"]


def test_parallel_stages_open_together_and_roll_up_on_last(super_admin_client):
    email, password = _make_org(super_admin_client)
    with _client_for(email, password) as org:
        _activate_policy(org, _two_stage_body(mode="parallel"))
        _add_user(org, "reviewer@acme.test", "governance_reviewer")
        _add_user(org, "riskowner@acme.test", "risk_owner")
        task, stages = _submit_and_stages(org)
    assert [s["status"] for s in stages] == ["open", "open"]
    with _client_for("riskowner@acme.test", "user-pw-123456") as riskowner:
        # parallel mode: stage 1 first is fine
        first = _decide(riskowner, stages[1]["stage_id"])
        assert first.status_code == 200, first.text
        assert first.json()["subject_status"] == "open"
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        second = _decide(reviewer, stages[0]["stage_id"])
        assert second.status_code == 200, second.text
        assert second.json()["subject_status"] == "approved"


def test_in_flight_work_keeps_the_policy_it_started_under(super_admin_client):
    email, password = _make_org(super_admin_client)
    with _client_for(email, password) as org:
        v1 = _activate_policy(org, _two_stage_body())
        _add_user(org, "reviewer@acme.test", "governance_reviewer")
        _add_user(org, "riskowner@acme.test", "risk_owner")
        task, stages = _submit_and_stages(org)
        assert all(s["policy_version"] == v1 for s in stages)

        # activating a three-stage policy must not rewrite the open review
        three_stage = _two_stage_body()
        three_stage["intake"]["tiers"]["high"]["stages"].append({"role": "governance_admin", "label": "Final sign-off"})
        _activate_policy(org, three_stage)
        unchanged = org.get(f"/api/approval-stages?subject_type=review_task&subject_id={task['task_id']}").json()["approval_stages"]
        assert len(unchanged) == 2
        assert all(s["policy_version"] == v1 for s in unchanged)

    # the in-flight review completes under its original two-stage policy
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        assert _decide(reviewer, stages[0]["stage_id"]).status_code == 200
    with _client_for("riskowner@acme.test", "user-pw-123456") as riskowner:
        done = _decide(riskowner, stages[1]["stage_id"])
        assert done.status_code == 200
        assert done.json()["subject_status"] == "approved"


def test_stage_role_authority_is_enforced_and_superset_roles_satisfy(super_admin_client):
    email, password = _make_org(super_admin_client)
    with _client_for(email, password) as org:
        _activate_policy(org, _two_stage_body())
        _add_user(org, "reviewer@acme.test", "governance_reviewer")
        _add_user(org, "ga@acme.test", "governance_admin")
        task, stages = _submit_and_stages(org)
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        assert _decide(reviewer, stages[0]["stage_id"]).status_code == 200
        # a bare reviewer lacks risk_owner authority for stage 1... but the
        # cross-stage rule fires first for this same reviewer, so check with a
        # second reviewer below
        _decide(reviewer, stages[1]["stage_id"])
    with _client_for(email, password) as org:
        _add_user(org, "reviewer2@acme.test", "governance_reviewer", password="rev2-pw-123456")
    with _client_for("reviewer2@acme.test", "rev2-pw-123456") as reviewer2:
        lacking = _decide(reviewer2, stages[1]["stage_id"])
        assert lacking.status_code == 403
        assert "risk_owner" in lacking.json()["detail"]
    with _client_for("ga@acme.test", "user-pw-123456") as admin:
        # governance_admin's permissions cover risk_owner's, so it satisfies the stage
        covered = _decide(admin, stages[1]["stage_id"])
        assert covered.status_code == 200, covered.text
        assert covered.json()["subject_status"] == "approved"


def test_stage_decisions_are_immutable_records(super_admin_client):
    """replaying the identical stage decision returns the original row and
    moves nothing; the generic decisions route refuses approval_stage targets"""
    email, password = _make_org(super_admin_client)
    with _client_for(email, password) as org:
        _activate_policy(org, _two_stage_body())
        _add_user(org, "reviewer@acme.test", "governance_reviewer")
        task, stages = _submit_and_stages(org)
    with _client_for("reviewer@acme.test", "user-pw-123456") as reviewer:
        bypass = reviewer.post(
            "/api/decisions",
            json={"target_type": "approval_stage", "target_id": stages[0]["stage_id"], "decision": "approve", "rationale": RATIONALE},
        )
        assert bypass.status_code == 400
        assert "approval-stages" in bypass.json()["detail"]

        first = _decide(reviewer, stages[0]["stage_id"])
        assert first.status_code == 200
        decision_id = first.json()["decision"]["decision_id"]

        from app.storage.workflow import record_decision

        replayed = record_decision("approval_stage", stages[0]["stage_id"], "approve", RATIONALE, "reviewer@acme.test")
        assert replayed["decision_id"] == decision_id
        assert replayed["created_at"] == first.json()["decision"]["created_at"]

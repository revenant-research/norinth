"""a policy version cannot put in force approval stages nobody can decide

a stage names the role whose authority decides it, and no person decides two
stages of one subject. a version whose stage list the organization's active
people cannot cover, one distinct person per stage, would leave every review
under it stuck. activation now refuses such a version, but only for the stage
lists it changes, so a gap the policy in force already has does not block
unrelated changes
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.test_policy_engine import _add_user, _client_for, _make_org  # noqa: E402


def _high(*roles: str) -> dict:
    return {
        "schema": "governance-policy/v1",
        "intake": {"tiers": {"high": {"stages": [{"role": role} for role in roles], "mode": "sequence"}}},
    }


def _draft(client, body) -> int:
    draft = client.post("/api/governance-policy/draft", json={"body": body})
    assert draft.status_code == 200, draft.text
    return draft.json()["policy"]["version"]


def test_a_stage_nobody_holds_is_refused_until_the_role_is_assigned(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        _add_user(org, "reviewer@acme.test", role="governance_reviewer")
        version = _draft(org, _high("governance_reviewer", "risk_owner"))

        diff = org.get(f"/api/governance-policy/diff?to_version={version}").json()
        assert len(diff["unstaffed"]) == 1 and diff["unstaffed"][0].startswith("intake.tiers.high")

        refused = org.post(f"/api/governance-policy/versions/{version}/activate")
        assert refused.status_code == 400, refused.text
        assert "nobody in the organization can decide" in refused.json()["detail"]
        assert org.get("/api/governance-policy").json()["policy"]["source"] == "default"

        _add_user(org, "owner@acme.test", role="risk_owner")
        assert org.get(f"/api/governance-policy/diff?to_version={version}").json()["unstaffed"] == []
        assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200


def test_each_stage_needs_a_different_person(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        _add_user(org, "reviewer1@acme.test", role="governance_reviewer")
        version = _draft(org, _high("governance_reviewer", "governance_reviewer"))
        assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 400

        _add_user(org, "reviewer2@acme.test", role="governance_reviewer")
        assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200


def test_a_role_with_more_authority_can_staff_the_stage(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        _add_user(org, "govadmin@acme.test", role="governance_admin")
        version = _draft(org, _high("governance_reviewer"))
        assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200


def test_a_suspended_person_does_not_count(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        _add_user(org, "reviewer@acme.test", role="governance_reviewer")
        _add_user(org, "owner@acme.test", role="risk_owner")
        from app.storage.raw_events import connect

        with connect() as connection:
            connection.execute("UPDATE platform_users SET status = 'suspended' WHERE user_ref = ?", ("owner@acme.test",))
        version = _draft(org, _high("governance_reviewer", "risk_owner"))
        assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 400


def test_an_unchanged_gap_does_not_block_other_changes(super_admin_client):
    """a new organization has nobody who can decide the default review stage,
    and can still tighten its gates"""
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as org:
        gates_only = {
            "schema": "governance-policy/v1",
            "gates": {"environments": {"prod": {"require_attested_evals": True}}},
        }
        version = _draft(org, gates_only)
        assert org.get(f"/api/governance-policy/diff?to_version={version}").json()["unstaffed"] == []
        assert org.post(f"/api/governance-policy/versions/{version}/activate").status_code == 200


def test_matching_reassigns_people_when_needed():
    from app.storage.policy_engine import _can_staff

    # taking x for the first stage leaves the second without anyone, unless x
    # moves to the second stage and y takes the first
    eligible = {"a": {"x", "y"}, "b": {"x"}}
    assert _can_staff(["a", "b"], eligible) is True
    assert _can_staff(["b", "b"], eligible) is False
    assert _can_staff(["a", "a", "b"], eligible) is False
    assert _can_staff([], eligible) is True

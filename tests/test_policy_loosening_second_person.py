"""a policy version that loosens the policy in force needs a second person

one config.write holder could draft a version that removed approval stages
or attested-eval requirements and activate it alone. a loosening version is
now activated by someone other than its author; tightening and neutral
changes stay single-person. policy_loosening compares the documents as the
resolvers read them, with the platform default filling the gaps
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import staff_policy_stages  # noqa: E402
from tests.test_policy_engine import _add_user, _client_for, _make_org  # noqa: E402

DEFAULT = {
    "schema": "governance-policy/v1",
    "intake": {
        "tiers": {
            "limited": {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"},
            "elevated": {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"},
            "high": {"stages": [{"role": "governance_reviewer"}], "mode": "sequence"},
        },
        "fields": [],
    },
    "gates": {"environments": {"*": {"require_attested_evals": False, "max_open_material_changes": 0}}},
    "vendors": {"stages": [{"role": "governance_reviewer"}], "recertify_days": 365},
}


def _high(stages, **extra):
    return {"schema": "governance-policy/v1", "intake": {"tiers": {"high": {"stages": stages, **extra}}}}


TWO_STAGE_HIGH = _high([{"role": "governance_reviewer"}, {"role": "risk_owner"}])
ONE_STAGE_HIGH = _high([{"role": "governance_reviewer"}])


def _loosening(old, new):
    from app.storage.policy_engine import policy_loosening

    return policy_loosening(old, new, DEFAULT)


def test_removing_an_approval_stage_loosens():
    assert _loosening(TWO_STAGE_HIGH, ONE_STAGE_HIGH) == [
        "intake.tiers.high: an approval stage is removed or its role replaced"
    ]
    assert _loosening(ONE_STAGE_HIGH, TWO_STAGE_HIGH) == []


def test_replacing_a_stage_role_loosens_but_labels_and_mode_do_not():
    replaced = _high([{"role": "governance_reviewer"}, {"role": "governance_admin"}])
    assert _loosening(TWO_STAGE_HIGH, replaced)
    relabeled = _high(
        [{"role": "risk_owner", "label": "Risk"}, {"role": "governance_reviewer", "label": "Security"}],
        mode="parallel",
    )
    assert _loosening(TWO_STAGE_HIGH, relabeled) == []


def test_dropping_a_tier_entry_falls_back_to_the_default_and_loosens():
    # a tenant document with no high entry resolves to the default's one stage
    assert _loosening(TWO_STAGE_HIGH, {"schema": "governance-policy/v1"}) == [
        "intake.tiers.high: an approval stage is removed or its role replaced"
    ]


def test_recertification_lengthened_or_removed_loosens():
    monthly = _high([{"role": "governance_reviewer"}], recertify_days=30)
    yearly = _high([{"role": "governance_reviewer"}], recertify_days=365)
    assert _loosening(monthly, yearly) == ["intake.tiers.high: recertification is less frequent or removed"]
    assert _loosening(monthly, ONE_STAGE_HIGH) == ["intake.tiers.high: recertification is less frequent or removed"]
    assert _loosening(yearly, monthly) == []
    vendors_long = {"schema": "governance-policy/v1", "vendors": {"stages": [{"role": "governance_reviewer"}], "recertify_days": 730}}
    assert _loosening(DEFAULT, vendors_long) == ["vendors: recertification is less frequent or removed"]


def test_dropping_attested_evals_for_an_environment_loosens():
    everywhere = {"schema": "governance-policy/v1", "gates": {"environments": {"*": {"require_attested_evals": True}}}}
    prod_only = {"schema": "governance-policy/v1", "gates": {"environments": {"prod": {"require_attested_evals": True}}}}
    assert _loosening(everywhere, prod_only) == ["gates.environments.*: attested evals are no longer required"]
    assert _loosening(prod_only, everywhere) == []
    assert _loosening(prod_only, DEFAULT) == ["gates.environments.prod: attested evals are no longer required"]


def test_removing_an_intake_field_or_its_required_tiers_loosens():
    field = {"key": "dpia_ref", "label": "DPIA reference", "required_tiers": ["high", "elevated"]}
    with_field = {"schema": "governance-policy/v1", "intake": {"fields": [field]}}
    fewer = {"schema": "governance-policy/v1", "intake": {"fields": [{**field, "required_tiers": ["high"]}]}}
    without = {"schema": "governance-policy/v1", "intake": {"fields": []}}
    assert _loosening(with_field, fewer) == ["intake.fields.dpia_ref: the field is required for fewer tiers"]
    assert _loosening(with_field, without) == ["intake.fields.dpia_ref: the field is removed"]
    assert _loosening(without, with_field) == []


def _draft(client, body) -> int:
    draft = client.post("/api/governance-policy/draft", json={"body": body})
    assert draft.status_code == 200, draft.text
    return draft.json()["policy"]["version"]


def test_author_cannot_activate_a_loosening_version(super_admin_client):
    email, password = _make_org(super_admin_client, "acme")
    with _client_for(email, password) as author:
        _add_user(author, "second@acme.test", role="org_admin")
        staff_policy_stages(author, "acme.test", TWO_STAGE_HIGH)
        # tightening the default: the author may activate it alone
        v1 = _draft(author, TWO_STAGE_HIGH)
        assert author.post(f"/api/governance-policy/versions/{v1}/activate").status_code == 200

        # removing the stage again loosens the policy in force
        v2 = _draft(author, ONE_STAGE_HIGH)
        diff = author.get(f"/api/governance-policy/diff?to_version={v2}").json()
        assert diff["loosens"] == ["intake.tiers.high: an approval stage is removed or its role replaced"]
        refused = author.post(f"/api/governance-policy/versions/{v2}/activate")
        assert refused.status_code == 403, refused.text
        assert "someone other than its author" in refused.json()["detail"]
        in_force = author.get("/api/governance-policy").json()["policy"]
        assert in_force["version"] == v1, "a refused activation must leave the policy in force unchanged"

    with _client_for("second@acme.test", "user-pw-123456") as second:
        activated = second.post(f"/api/governance-policy/versions/{v2}/activate")
        assert activated.status_code == 200, activated.text
        entries = second.get("/api/audit-logs?action=policy.activate").json()["audit_logs"]
        latest = entries[0]
        detail = latest["detail"] if isinstance(latest["detail"], dict) else json.loads(latest["detail"])
        assert detail["version"] == v2
        assert detail["author"] == email
        assert detail["loosens"] == ["intake.tiers.high: an approval stage is removed or its role replaced"]

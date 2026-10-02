"""shared test helpers"""

from __future__ import annotations


def login_and_activate(test_client, email: str, password: str, new_password: str | None = None):
    """log a user in and complete first-login password rotation if required"""
    login = test_client.post("/api/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    if login.json()["user"].get("must_change_password"):
        rotated = new_password or f"{password}-rotated-1"
        changed = test_client.post(
            "/api/auth/change-password",
            json={"current_password": password, "new_password": rotated},
        )
        assert changed.status_code == 200, changed.text
    return test_client



def staff_policy_stages(org_client, domain: str, body: dict) -> None:
    """give an organization one active person per approval-stage position in
    a policy document, so the version can be activated

    activation refuses stage lists nobody can decide. position i of any stage
    list is staffed by the same person across sections, and an existing
    person is reused, so repeated calls are harmless
    """
    sections = [entry.get("stages") or [] for entry in ((body.get("intake") or {}).get("tiers") or {}).values()]
    sections.append((body.get("vendors") or {}).get("stages") or [])
    wanted = {(index, stage["role"]) for stages in sections for index, stage in enumerate(stages)}
    for index, role in sorted(wanted):
        email = f"staff-{index}-{role.replace('_', '-')}@{domain}"
        created = org_client.post(
            "/api/org/users", json={"email": email, "display_name": f"staff {index} {role}", "password": "staff-pw-123456"}
        )
        if created.status_code != 200:
            continue  # already staffed by an earlier call
        granted = org_client.post("/api/org/role-assignments", json={"user_ref": email, "role": role})
        assert granted.status_code == 200, granted.text

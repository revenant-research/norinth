# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import json
import os
import sys
from http.cookiejar import CookieJar
from typing import Any
from urllib import error, request

# live check of identity, multi-tenancy, rbac, intake, and decision paths
# exercises provisioning (super admin -> org -> org admin -> user -> role) and the
# governance workflow (intake -> routed review -> decision), and asserts that
# unauthenticated/unauthorized calls are rejected and maker-checker is enforced
# deployment-gate and incident flows are telemetry-driven and not covered here

PLATFORM_URL = os.getenv("NORINTH_PLATFORM_URL", "http://127.0.0.1:8001")
SUPER_ADMIN_EMAIL = os.getenv("NORINTH_SUPER_ADMIN_EMAIL", "admin@norinth.local")
SUPER_ADMIN_PASSWORD = os.getenv("NORINTH_SUPER_ADMIN_PASSWORD", "norinth-admin")

REVIEW_QUEUE_POLICY = {
    "policy_id": "QUEUE-INTAKE-REVIEW",
    "task_type": "intake_review",
    "assigned_role": "governance_admin",
    "due_days": 7,
    "escalation_days": 2,
    "source": "verification_config",
}


ROTATED_SUPER_ADMIN_PASSWORD = f"{SUPER_ADMIN_PASSWORD}-verified-1"


def assert_condition(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class Session:
    """minimal cookie-aware http session over urllib"""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))

    def get(self, path: str, expected_status: int = 200) -> dict[str, Any]:
        return self._send("GET", path, None, expected_status)

    def post(self, path: str, payload: dict[str, Any] | None = None, expected_status: int = 200) -> dict[str, Any]:
        return self._send("POST", path, payload, expected_status)

    def _send(self, method: str, path: str, payload: dict[str, Any] | None, expected_status: int) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        http_request = request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(http_request, timeout=30) as response:
                body = response.read().decode("utf-8")
                assert_condition(
                    response.status == expected_status,
                    f"expected {expected_status} for {method} {path}, got {response.status}",
                )
                return json.loads(body) if body else {}
        except error.HTTPError as http_error:
            body = http_error.read().decode("utf-8")
            assert_condition(
                http_error.code == expected_status,
                f"expected {expected_status} for {method} {path}, got {http_error.code}: {body}",
            )
            return {"status": http_error.code, "body": body}


def login_super_admin(session: Session) -> dict[str, Any]:
    """log the super admin in, rotating the first-login password if required"""
    try:
        login = session.post(
            "/api/auth/login",
            {"email": SUPER_ADMIN_EMAIL, "password": SUPER_ADMIN_PASSWORD},
        )
    except AssertionError:
        # default password already rotated by a previous run
        return session.post(
            "/api/auth/login",
            {"email": SUPER_ADMIN_EMAIL, "password": ROTATED_SUPER_ADMIN_PASSWORD},
        )
    if login["user"].get("must_change_password"):
        session.post(
            "/api/auth/change-password",
            {"current_password": SUPER_ADMIN_PASSWORD, "new_password": ROTATED_SUPER_ADMIN_PASSWORD},
        )
    return login


def login_and_activate(session: Session, email: str, password: str) -> dict[str, Any]:
    """log a fresh user in and rotate the first-login password; the server 403s every call until it's changed"""
    login = session.post("/api/auth/login", {"email": email, "password": password})
    if login["user"].get("must_change_password"):
        session.post(
            "/api/auth/change-password",
            {"current_password": password, "new_password": f"{password}-rotated1"},
        )
    return login


def main() -> int:
    health = Session(PLATFORM_URL).get("/health")
    assert_condition(health["ok"], "platform health check failed")

    # 1. unauthenticated reads must be rejected
    anon = Session(PLATFORM_URL)
    anon.get("/api/applications", expected_status=401)
    anon.get("/api/admin/organizations", expected_status=401)

    # 2. super admin signs in and provisions an org with its admin. the seeded
    #    super admin has must_change_password=True, so the first-login password
    #    must be rotated before the rest of the api works; a re-run falls back to
    #    the rotated password
    superadmin = Session(PLATFORM_URL)
    me = login_super_admin(superadmin)
    assert_condition(me["user"]["is_super_admin"], "seeded user is not a super admin")

    org = superadmin.post(
        "/api/admin/organizations",
        {
            "tenant_id": "verify-co",
            "name": "Verify Co",
            "admin_email": "orgadmin@verify-co.test",
            "admin_display_name": "Verify Org Admin",
            "admin_password": "orgadminpass1",
        },
    )
    assert_condition(org["organization"]["tenant_id"] == "verify-co", "organization was not provisioned")

    # second tenant, to prove cross-tenant isolation later
    superadmin.post(
        "/api/admin/organizations",
        {
            "tenant_id": "other-co",
            "name": "Other Co",
            "admin_email": "orgadmin@other-co.test",
            "admin_display_name": "Other Org Admin",
            "admin_password": "otheradminpass1",
        },
    )
    organizations = superadmin.get("/api/admin/organizations")["organizations"]
    assert_condition(len(organizations) >= 2, "organizations were not listed for the super admin")

    # 3. org admin signs in and provisions a reviewer in their org
    orgadmin = Session(PLATFORM_URL)
    login_and_activate(orgadmin, "orgadmin@verify-co.test", "orgadminpass1")
    orgadmin.post(
        "/api/org/users",
        {"email": "reviewer@verify-co.test", "display_name": "Verify Reviewer", "password": "reviewerpass1"},
    )
    orgadmin.post("/api/org/role-assignments", {"user_ref": "reviewer@verify-co.test", "role": "governance_admin"})
    # no-role user: proves auth alone doesn't grant authorization
    orgadmin.post(
        "/api/org/users",
        {"email": "noroles@verify-co.test", "display_name": "No Roles", "password": "norolespass1"},
    )

    # 4. route intake reviews to the reviewer role
    orgadmin.post("/api/review-queue-policies", REVIEW_QUEUE_POLICY)

    # 5. org admin submits a use case; risk tier is derived automatically
    intake = orgadmin.post(
        "/api/intake",
        {
            "application_name": "Verify Claims Bot",
            "use_case": "claims triage",
            "description": "Triage inbound claims and flag missing evidence.",
            "intended_purpose": "Assist adjusters with first-pass claim review.",
            "data_sensitivity": "restricted",
            "autonomy_level": "supervised",
            "affects_individuals": True,
        },
    )
    assert_condition(intake["intake"]["risk_tier"] == "high", "restricted/affecting-individuals intake should be high risk")

    review_tasks = orgadmin.get("/api/review-tasks")["review_tasks"]
    intake_task = next((task for task in review_tasks if task["task_type"] == "intake_review"), None)
    assert_condition(intake_task is not None, "intake did not route a review task")
    assert_condition(intake_task["assigned_role"] == "governance_admin", "intake review was not routed to the reviewer role")

    # 6. separation of duties: submitter can't decide their own intake
    orgadmin.post(
        "/api/decisions",
        {"target_type": "review_task", "target_id": intake_task["task_id"], "decision": "approve", "rationale": "self-approval"},
        expected_status=403,
    )

    # 7. authenticated but unauthorized user can't decide either
    noroles = Session(PLATFORM_URL)
    login_and_activate(noroles, "noroles@verify-co.test", "norolespass1")
    noroles.post(
        "/api/decisions",
        {"target_type": "review_task", "target_id": intake_task["task_id"], "decision": "approve", "rationale": "no permission"},
        expected_status=403,
    )

    # 8. reviewer (different user, has the role) records the decision
    reviewer = Session(PLATFORM_URL)
    login_and_activate(reviewer, "reviewer@verify-co.test", "reviewerpass1")
    reviewer.post(
        "/api/decisions",
        {"target_type": "review_task", "target_id": intake_task["task_id"], "decision": "approve", "rationale": "Evidence reviewed; approving intake."},
    )
    decisions = reviewer.get("/api/decisions")["decisions"]
    assert_condition(any(d["target_id"] == intake_task["task_id"] for d in decisions), "review decision did not persist")

    # 9. tenant isolation: other org's admin can't see verify-co records
    other = Session(PLATFORM_URL)
    login_and_activate(other, "orgadmin@other-co.test", "otheradminpass1")
    other_intake = other.get("/api/intake")["intake"]
    assert_condition(all(record["tenant_id"] != "verify-co" for record in other_intake), "tenant isolation breach on intake")
    other_scopes = other.get("/api/scopes")
    assert_condition(other_scopes["tenants"] == ["other-co"], "tenant scope leaked across organizations")

    # 10. lifecycle: org admin recertifies the use case
    orgadmin.post(f"/api/intake/{intake['intake']['intake_id']}/recertify", {"rationale": "Annual recertification complete."})

    # 11. audit trail captured the identity and governance actions
    audit = superadmin.get("/api/audit-logs")["audit_logs"]
    actions = {entry["action"] for entry in audit}
    for expected in {"auth.login", "org.provision", "user.create", "role.assign", "intake.submit", "review.decide", "lifecycle.recertify"}:
        assert_condition(expected in actions, f"audit log missing action: {expected}")

    print(
        json.dumps(
            {
                "organizations": len(organizations),
                "intake_risk_tier": intake["intake"]["risk_tier"],
                "intake_review_routed": intake_task["assigned_role"],
                "decisions": len(decisions),
                "audit_actions": sorted(actions),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - print a clear failure for ci
        print(f"verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

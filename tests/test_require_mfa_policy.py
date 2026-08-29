"""an organization can require a second factor on local-password accounts

the policy must be lockout-proof: password login keeps working and the
session can always reach the enrollment endpoints, so flipping the flag can
never strand an organization. sso/scim accounts (no local password) are
exempt — their factor lives at the idp.
"""

from __future__ import annotations

import base64
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _code(secret: str, offset: int = 0) -> str:
    from app.services import totp

    key = base64.b32decode(secret, casefold=True)
    return totp._hotp(key, totp.current_counter() + offset)


def _enroll(client) -> str:
    secret = client.post("/api/auth/mfa/setup").json()["secret"]
    enabled = client.post("/api/auth/mfa/enable", json={"code": _code(secret)})
    assert enabled.status_code == 200, enabled.text
    return secret


def _org_admin(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant,
            "name": tenant,
            "admin_email": f"a@{tenant}.test",
            "admin_display_name": "A",
            "admin_password": f"{tenant}-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    return org


def _member(org, tenant: str, email: str):
    from app.main import app
    from fastapi.testclient import TestClient

    org.post("/api/org/users", json={"email": email, "display_name": "M", "password": "member-pass-123"})
    member = TestClient(app)
    login_and_activate(member, email, "member-pass-123")
    return member


def test_policy_walls_unenrolled_members_into_enrollment(super_admin_client):
    org = _org_admin(super_admin_client, "acme")
    _enroll(org)  # the admin enrolls first (required to turn the policy on)
    member = _member(org, "acme", "m@acme.test")

    assert org.post("/api/org/security-policy", json={"require_mfa": True}).status_code == 200

    # the member's existing session hits the wall on governance data...
    refused = member.get("/api/systems")
    assert refused.status_code == 403
    assert "multi-factor" in refused.json()["detail"].lower()
    # ...but the enrollment surface and self-service stay reachable
    assert member.get("/api/auth/me").status_code == 200
    assert member.get("/api/auth/mfa").status_code == 200
    profile = member.get("/api/auth/me").json()["user"]
    assert profile["mfa_enrollment_required"] is True

    _enroll(member)
    assert member.get("/api/systems").status_code == 200
    assert member.get("/api/auth/me").json()["user"]["mfa_enrollment_required"] is False
    member.close()
    org.close()


def test_enrolled_members_are_untouched_by_the_policy(super_admin_client):
    org = _org_admin(super_admin_client, "beta")
    _enroll(org)
    member = _member(org, "beta", "m@beta.test")
    _enroll(member)

    assert org.post("/api/org/security-policy", json={"require_mfa": True}).status_code == 200
    assert member.get("/api/systems").status_code == 200
    member.close()
    org.close()


def test_admin_without_mfa_cannot_turn_the_policy_on(super_admin_client):
    """without this guard the admin's next request lands behind the wall —
    including the request that could turn the policy back off"""
    org = _org_admin(super_admin_client, "gamma")
    refused = org.post("/api/org/security-policy", json={"require_mfa": True})
    assert refused.status_code == 400
    assert "your own second factor" in refused.json()["detail"].lower()
    # and the org is not left half-flagged
    assert org.get("/api/org/security-policy").json()["require_mfa"] is False
    org.close()


def test_accounts_without_a_local_password_are_exempt(super_admin_client):
    """sso/scim-provisioned users authenticate at the idp; the org policy
    must not wall their sessions"""
    from app.storage.raw_events import connect

    org = _org_admin(super_admin_client, "delta")
    _enroll(org)
    member = _member(org, "delta", "sso@delta.test")
    # simulate an idp-provisioned account: no local password (scim creates
    # users with password_hash="")
    with connect() as connection:
        connection.execute(
            "UPDATE platform_users SET password_hash = '' WHERE user_ref = ?", ("sso@delta.test",)
        )

    assert org.post("/api/org/security-policy", json={"require_mfa": True}).status_code == 200
    assert member.get("/api/systems").status_code == 200
    assert member.get("/api/auth/me").json()["user"]["mfa_enrollment_required"] is False
    member.close()
    org.close()


def test_policy_toggle_requires_user_manage_and_is_audited(super_admin_client):
    org = _org_admin(super_admin_client, "epsilon")
    _enroll(org)
    member = _member(org, "epsilon", "m@epsilon.test")

    assert member.post("/api/org/security-policy", json={"require_mfa": True}).status_code == 403
    assert org.post("/api/org/security-policy", json={"require_mfa": True}).status_code == 200

    entries = super_admin_client.get("/api/audit-logs?action=org.security_policy").json()["audit_logs"]
    assert entries and entries[0]["tenant_id"] == "epsilon"
    member.close()
    org.close()


def test_policy_off_changes_nothing(super_admin_client):
    org = _org_admin(super_admin_client, "zeta")
    member = _member(org, "zeta", "m@zeta.test")
    assert member.get("/api/systems").status_code == 200
    assert member.get("/api/auth/me").json()["user"]["mfa_enrollment_required"] is False
    member.close()
    org.close()

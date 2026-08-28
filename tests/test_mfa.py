"""totp multi-factor authentication

the F500 evaluation's first blocker: no MFA anywhere, and structurally none
possible for the super admin (tenant-less, never federated). these tests
cover enrollment, the login challenge, code single-use, recovery codes, and
the structural point itself — an operator password reset no longer opens an
enrolled account.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _code(secret: str, offset: int = 0) -> str:
    import base64

    from app.services import totp

    key = base64.b32decode(secret, casefold=True)
    return totp._hotp(key, totp.current_counter() + offset)


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


def _enroll(client) -> tuple[str, list[str]]:
    """set up + enable mfa on the client's account; returns (secret, recovery codes)"""
    setup = client.post("/api/auth/mfa/setup")
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert "otpauth://totp/" in setup.json()["otpauth_uri"]
    enabled = client.post("/api/auth/mfa/enable", json={"code": _code(secret)})
    assert enabled.status_code == 200, enabled.text
    codes = enabled.json()["recovery_codes"]
    assert len(codes) == 10
    return secret, codes


# --- totp algorithm ---------------------------------------------------------------


def test_totp_verify_and_replay_protection():
    from app.services import totp

    secret = totp.generate_secret()
    code = _code(secret)
    counter = totp.verify_code(secret, code, last_counter=None)
    assert counter is not None
    # the same code again is a replay: counters must advance
    assert totp.verify_code(secret, code, last_counter=counter) is None
    # a neighbouring step is accepted for clock skew
    assert totp.verify_code(secret, _code(secret, offset=1), last_counter=counter) is not None
    assert totp.verify_code(secret, "000000", last_counter=None) in (None,)
    assert totp.verify_code(secret, "not-a-code", last_counter=None) is None


# --- enrollment and login ---------------------------------------------------------


def test_enrolled_login_requires_the_second_factor(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client, "acme")
    secret, _ = _enroll(org)
    org.close()

    fresh = TestClient(app)
    first = fresh.post("/api/auth/login", json={"email": "a@acme.test", "password": "acme-admin-pw-1-rotated-1"})
    assert first.status_code == 200, first.text
    body = first.json()
    assert body.get("mfa_required") is True
    assert "user" not in body, "profile must not be revealed before the second factor"
    assert "norinth_session" not in fresh.cookies, "password step must not issue a session"

    # a fresh code (the enable step consumed the current counter)
    verify = fresh.post("/api/auth/mfa/verify", json={"challenge": body["challenge"], "code": _code(secret, offset=1)})
    assert verify.status_code == 200, verify.text
    assert verify.json()["user"]["user_ref"] == "a@acme.test"
    assert fresh.get("/api/auth/me").status_code == 200
    fresh.close()


def test_wrong_codes_burn_the_challenge(super_admin_client):
    from app.api.auth import MFA_CHALLENGE_MAX_ATTEMPTS
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client, "beta")
    _enroll(org)
    org.close()

    fresh = TestClient(app)
    challenge = fresh.post(
        "/api/auth/login", json={"email": "a@beta.test", "password": "beta-admin-pw-1-rotated-1"}
    ).json()["challenge"]
    for _ in range(MFA_CHALLENGE_MAX_ATTEMPTS):
        assert fresh.post("/api/auth/mfa/verify", json={"challenge": challenge, "code": "000000"}).status_code == 401
    # the challenge is gone now, even with a would-be-valid shape
    burned = fresh.post("/api/auth/mfa/verify", json={"challenge": challenge, "code": "123456"})
    assert burned.status_code == 401
    assert "challenge" in burned.json()["detail"].lower()
    fresh.close()


def test_recovery_code_works_exactly_once(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client, "gamma")
    _, codes = _enroll(org)
    org.close()

    def challenge_for(client):
        return client.post(
            "/api/auth/login", json={"email": "a@gamma.test", "password": "gamma-admin-pw-1-rotated-1"}
        ).json()["challenge"]

    fresh = TestClient(app)
    used = codes[0]
    ok = fresh.post("/api/auth/mfa/verify", json={"challenge": challenge_for(fresh), "recovery_code": used})
    assert ok.status_code == 200, ok.text

    second = TestClient(app)
    replay = second.post("/api/auth/mfa/verify", json={"challenge": challenge_for(second), "recovery_code": used})
    assert replay.status_code == 401, "a recovery code must be single-use"
    fresh.close()
    second.close()


def test_disable_requires_both_factors(super_admin_client):
    org = _org_admin(super_admin_client, "delta")
    secret, codes = _enroll(org)

    refused = org.post("/api/auth/mfa/disable", json={"password": "wrong-password-11", "code": _code(secret, offset=1)})
    assert refused.status_code == 401
    refused = org.post("/api/auth/mfa/disable", json={"password": "delta-admin-pw-1-rotated-1", "code": "000000"})
    assert refused.status_code == 401

    ok = org.post(
        "/api/auth/mfa/disable",
        json={"password": "delta-admin-pw-1-rotated-1", "recovery_code": codes[1]},
    )
    assert ok.status_code == 200, ok.text
    assert org.get("/api/auth/mfa").json()["enabled"] is False
    org.close()


# --- the structural point ---------------------------------------------------------


def test_operator_password_reset_cannot_open_an_enrolled_account(super_admin_client):
    """the eval reproduced a takeover: operator mints a password, signs in as the
    org admin. with mfa enrolled the minted password stops at the challenge."""
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client, "epsilon")
    _enroll(org)
    org.close()

    reset = super_admin_client.post("/api/admin/users/a@epsilon.test/reset-password")
    assert reset.status_code == 200
    temp_password = reset.json()["temporary_password"]

    operator_browser = TestClient(app)
    attempt = operator_browser.post("/api/auth/login", json={"email": "a@epsilon.test", "password": temp_password})
    assert attempt.status_code == 200
    assert attempt.json().get("mfa_required") is True
    assert "norinth_session" not in operator_browser.cookies
    # no session, no profile, no tenant data — the operator stops here
    assert operator_browser.get("/api/auth/me").status_code == 401
    operator_browser.close()


def test_operator_has_no_mfa_reset(super_admin_client):
    """an operator mfa reset plus an operator password reset would re-open the
    takeover; the platform plane deliberately has no such endpoint"""
    response = super_admin_client.post("/api/admin/users/anyone@x.test/mfa/reset")
    assert response.status_code in (404, 405)


def test_org_admin_can_reset_a_users_mfa(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client, "zeta")
    org.post("/api/org/users", json={"email": "u@zeta.test", "display_name": "U", "password": "u-password-1234"})

    member = TestClient(app)
    login_and_activate(member, "u@zeta.test", "u-password-1234")
    _enroll(member)

    reset = org.post("/api/org/users/u@zeta.test/mfa/reset")
    assert reset.status_code == 200, reset.text
    # sessions are dropped with the second factor
    assert member.get("/api/auth/me").status_code == 401

    back = TestClient(app)
    again = back.post("/api/auth/login", json={"email": "u@zeta.test", "password": "u-password-1234-rotated-1"})
    assert again.status_code == 200 and "user" in again.json()
    member.close()
    back.close()
    org.close()


def test_admin_user_listings_never_carry_mfa_secrets(super_admin_client):
    org = _org_admin(super_admin_client, "eta")
    _enroll(org)

    listing = org.get("/api/org/users").json()["users"]
    me = next(u for u in listing if u["user_ref"] == "a@eta.test")
    assert "mfa_secret" not in me and "mfa_pending_secret" not in me
    assert me.get("mfa_enabled_at"), "admins may see who is enrolled"
    org.close()

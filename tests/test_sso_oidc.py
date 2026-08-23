"""End-to-end tests for OpenID Connect SSO with JIT provisioning.

A fake identity provider is substituted for the outbound HTTP calls. It serves a
real JWKS and issues genuinely RS256-signed id_tokens, so the full verification
path (signature against JWKS, iss/aud/exp, nonce binding, PKCE verifier) is
exercised exactly as it would be against Okta/Entra/Auth0 — with no network.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time
from urllib import parse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

ISSUER = "https://idp.example.test"
CLIENT_ID = "norinth-client"


class FakeIdP:
    """Minimal OIDC provider: discovery, JWKS, and a token endpoint that checks
    the PKCE verifier and mints a signed id_token bound to the login nonce."""

    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "test-key-1"
        self.pending_nonce: str | None = None
        self.pending_challenge: str | None = None
        self.email = "jane@acme.test"
        self.token_requests: list[dict] = []

    def jwks(self) -> dict:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        jwk["kid"] = self.kid
        jwk["use"] = "sig"
        jwk["alg"] = "RS256"
        return {"keys": [jwk]}

    def discovery(self) -> dict:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
        }

    def mint_id_token(self, nonce: str, *, issuer: str = ISSUER, audience: str = CLIENT_ID, email: str | None = None) -> str:
        now = int(time.time())
        claims = {
            "iss": issuer,
            "aud": audience,
            "sub": "user-123",
            "email": email or self.email,
            "name": "Jane Doe",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": self.kid})

    # --- HTTP substitutes
    def get_json(self, url: str, timeout: float = 10.0) -> dict:
        if url.endswith("/.well-known/openid-configuration"):
            return self.discovery()
        if url.endswith("/jwks"):
            return self.jwks()
        raise AssertionError(f"unexpected GET {url}")

    def post_form(self, url: str, data: dict, timeout: float = 10.0) -> dict:
        assert url == f"{ISSUER}/token"
        self.token_requests.append(data)
        # PKCE: the verifier must match the challenge sent at /authorize.
        import base64
        import hashlib

        digest = hashlib.sha256(data["code_verifier"].encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert challenge == self.pending_challenge, "PKCE verifier did not match challenge"
        assert data["code"] == "good-code"
        return {"access_token": "at", "id_token": self.mint_id_token(self.pending_nonce), "token_type": "Bearer"}


@pytest.fixture
def idp(monkeypatch):
    provider = FakeIdP()
    import app.services.sso as sso_service

    monkeypatch.setattr(sso_service, "http_get_json", provider.get_json)
    monkeypatch.setattr(sso_service, "http_post_form", provider.post_form)
    return provider


def _org_admin(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    return org


def _configure(org, **overrides):
    payload = {"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "s3cret", **overrides}
    resp = org.put("/api/org/sso", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()["sso"]
    assert "client_secret" not in body  # never echoed
    assert body["jwks_uri"] == f"{ISSUER}/jwks"  # discovery ran
    return body


def _start_and_capture(client, idp):
    start = client.get("/api/auth/sso/acme/start", follow_redirects=False)
    assert start.status_code == 302
    params = dict(parse.parse_qsl(parse.urlsplit(start.headers["location"]).query))
    assert params["code_challenge_method"] == "S256"
    assert params["scope"] == "openid email profile"
    idp.pending_nonce = params["nonce"]
    idp.pending_challenge = params["code_challenge"]
    return params["state"]


def test_full_sso_login_with_jit_provisioning(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    _configure(org)

    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        cb = browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False)
        assert cb.status_code == 302, cb.text
        assert "norinth_session" in cb.headers.get("set-cookie", "")

        me = browser.get("/api/auth/me")
        assert me.status_code == 200, me.text
        user = me.json()["user"]
        assert user["email"] == "jane@acme.test"
        assert user["tenant_id"] == "acme"
        assert user["must_change_password"] is False
        # JIT default is the read-only viewer: authenticate and view, but no
        # decision rights until an admin elevates the user (audit finding M100).
        assert "review.decide" not in user["permissions"]

        # The PKCE verifier and client secret went to the token endpoint.
        assert idp.token_requests[0]["client_secret"] == "s3cret"

    org.close()


def test_sso_user_cannot_password_login(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    _configure(org)
    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False)

    # The JIT-provisioned account has no password; any password must fail.
    from fastapi.testclient import TestClient as TC

    with TC(app) as other:
        resp = other.post("/api/auth/login", json={"email": "jane@acme.test", "password": "anything"})
        assert resp.status_code == 401
    org.close()


def test_state_is_single_use_and_unknown_state_rejected(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    _configure(org)
    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        assert browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False).status_code == 302
        # Replaying the same state must fail (consumed).
        assert browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False).status_code == 401
        assert browser.get("/api/auth/sso/callback?code=good-code&state=forged", follow_redirects=False).status_code == 401
    org.close()


def test_id_token_with_wrong_audience_is_rejected(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    _configure(org)

    def bad_post(url, data, timeout=10.0):
        return {"id_token": idp.mint_id_token(idp.pending_nonce, audience="someone-else")}

    import app.services.sso as sso_service

    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        sso_service.http_post_form = bad_post
        resp = browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False)
        assert resp.status_code == 401
        assert "verification failed" in resp.json()["detail"]
    org.close()


def test_email_domain_restriction(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    _configure(org, allowed_email_domain="acme.test")
    idp.email = "intruder@other.test"
    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        resp = browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False)
        assert resp.status_code == 401
        assert "domain" in resp.json()["detail"]
    org.close()


def test_jit_never_grants_admin_role(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    # Even if an admin sets the default JIT role to org_admin, provisioning
    # downgrades it (separation of duties).
    _configure(org, default_role="org_admin")
    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False)
        perms = browser.get("/api/auth/me").json()["user"]["permissions"]
        assert "role.assign" not in perms
        assert "user.manage" not in perms
    org.close()


def test_admin_can_configure_a_decision_default(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org_admin(super_admin_client)
    # An admin who deliberately configures governance_reviewer as the JIT default
    # owns that choice; the fix only changes the *unconfigured* fallback (M100).
    _configure(org, default_role="governance_reviewer")
    with TestClient(app) as browser:
        state = _start_and_capture(browser, idp)
        browser.get(f"/api/auth/sso/callback?code=good-code&state={state}", follow_redirects=False)
        perms = browser.get("/api/auth/me").json()["user"]["permissions"]
        assert "review.decide" in perms
    org.close()


def test_sso_config_requires_org_admin(super_admin_client, idp):
    # Super admin has no tenant and cannot configure tenant SSO.
    resp = super_admin_client.put(
        "/api/org/sso", json={"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "x"}
    )
    assert resp.status_code == 403

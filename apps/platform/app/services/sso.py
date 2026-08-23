"""OpenID Connect authorization-code login with PKCE and JIT provisioning.

Flow:
  1. start_login(tenant)  -> authorization URL (state + nonce + PKCE stored)
  2. IdP redirects back with ?code&state
  3. complete_login(code, state) -> exchange code at the token endpoint, verify
     the id_token signature (RS256 against the provider's JWKS) and claims
     (iss, aud, exp, nonce), then find-or-create the user inside the tenant and
     grant the tenant's configured default role (just-in-time provisioning).

SSO-provisioned users have no password (an empty hash), so password login is
impossible for them; the IdP is the sole authority. The outbound HTTP calls are
isolated in `http_get_json` / `http_post_form` so tests can substitute a fake
identity provider without a network.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from urllib import parse, request

import jwt

from app.services.authorization import ADMINISTRATION_ROLES
from app.services.net_guard import validate_external_url
from app.storage.sso import consume_login_state, create_login_state, load_sso_configuration
from app.storage.workflow import create_platform_user, get_user_by_email, upsert_role_assignment


class SsoError(Exception):
    pass


# --- outbound HTTP (monkeypatched in tests) -------------------------------------


def http_get_json(url: str, timeout: float = 10.0) -> dict[str, Any]:
    validate_external_url(url)
    with request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - validated above
        return json.loads(response.read().decode("utf-8"))


def http_post_form(url: str, data: dict[str, str], timeout: float = 10.0) -> dict[str, Any]:
    body = parse.urlencode(data).encode("utf-8")
    validate_external_url(url)
    req = request.Request(url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
    with request.urlopen(req, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


# --- discovery -------------------------------------------------------------------


def discover(issuer: str) -> dict[str, str]:
    """Fetch the provider's OpenID configuration and return the endpoints we need."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = http_get_json(url)
    try:
        return {
            "issuer": doc.get("issuer", issuer),
            "authorization_endpoint": doc["authorization_endpoint"],
            "token_endpoint": doc["token_endpoint"],
            "jwks_uri": doc["jwks_uri"],
        }
    except KeyError as error:
        raise SsoError(f"OpenID configuration is missing {error}") from error


# --- login ------------------------------------------------------------------------


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def start_login(tenant_id: str, redirect_uri: str) -> tuple[str, str]:
    """Return (authorization URL, state). The state is also set as a browser
    cookie by the caller and re-checked at the callback, binding the flow to the
    browser that started it so a victim cannot be signed into an attacker's
    account via a planted callback (audit finding M97)."""
    config = load_sso_configuration(tenant_id)
    if config is None or not config.get("enabled"):
        raise SsoError("SSO is not configured for this organization")
    state = create_login_state(tenant_id)
    params = {
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state["state"],
        "nonce": state["nonce"],
        "code_challenge": _pkce_challenge(state["code_verifier"]),
        "code_challenge_method": "S256",
    }
    return f"{config['authorization_endpoint']}?{parse.urlencode(params)}", state["state"]


def _verify_id_token(id_token: str, config: dict[str, Any], nonce: str) -> dict[str, Any]:
    jwks = http_get_json(config["jwks_uri"])
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as error:
        raise SsoError("id_token is not a valid JWT") from error
    key = None
    for candidate in jwks.get("keys", []):
        if candidate.get("kid") == header.get("kid") or (header.get("kid") is None and len(jwks.get("keys", [])) == 1):
            key = jwt.PyJWK(candidate).key
            break
    if key is None:
        raise SsoError("no matching signing key in the provider's JWKS")
    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=["RS256"],
            audience=config["client_id"],
            issuer=config["issuer"],
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as error:
        raise SsoError(f"id_token verification failed: {error}") from error
    if claims.get("nonce") != nonce:
        raise SsoError("id_token nonce mismatch")
    return claims


def complete_login(code: str, state: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange the code, verify the identity, and return the provisioned user."""
    login_state = consume_login_state(state)
    if login_state is None:
        raise SsoError("login state is unknown or expired")
    tenant_id = login_state["tenant_id"]
    config = load_sso_configuration(tenant_id)
    if config is None or not config.get("enabled"):
        raise SsoError("SSO is not configured for this organization")

    tokens = http_post_form(
        config["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code_verifier": login_state["code_verifier"],
        },
    )
    id_token = tokens.get("id_token")
    if not id_token:
        raise SsoError("token response did not include an id_token")
    claims = _verify_id_token(id_token, config, login_state["nonce"])

    email = (claims.get("email") or "").strip().lower()
    if not email:
        raise SsoError("identity provider did not supply an email claim")
    domain = config.get("allowed_email_domain")
    if domain and not email.endswith("@" + domain.lower()):
        raise SsoError("email domain is not permitted for this organization")

    return _provision_user(tenant_id, email, claims, config)


def _provision_user(tenant_id: str, email: str, claims: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    existing = get_user_by_email(email)
    if existing is not None:
        if existing.get("tenant_id") != tenant_id:
            # A federated identity may never be attached to a different tenant's
            # account by signing in through another org's IdP.
            raise SsoError("this account belongs to a different organization")
        if existing.get("status") != "active":
            raise SsoError("account is not active")
        return existing

    display_name = claims.get("name") or claims.get("preferred_username") or email
    user = create_platform_user(
        user_ref=email,
        display_name=display_name,
        email=email,
        password_hash="",  # SSO-only: password login impossible
        status="active",
        platform_role=None,
        tenant_id=tenant_id,
        must_change_password=False,
    )
    # Least privilege: an unconfigured default provisions a read-only viewer, not
    # a reviewer with review.decide, so authenticating at the IdP never grants
    # decision rights on its own (audit finding M100). An org admin sets
    # default_role deliberately to grant more, and can never auto-grant admin.
    default_role = config.get("default_role") or "governance_viewer"
    if default_role in ADMINISTRATION_ROLES:
        default_role = "governance_viewer"
    upsert_role_assignment(
        {
            "user_ref": email,
            "role": default_role,
            "status": "active",
            "tenant_id": tenant_id,
            "project": None,
            "environment": None,
        }
    )
    return user

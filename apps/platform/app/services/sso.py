"""openid connect authorization-code login with pkce and jit provisioning

flow:
  1. start_login(tenant)  -> authorization url (state + nonce + pkce stored)
  2. idp redirects back with ?code&state
  3. complete_login(code, state) -> exchange code at the token endpoint, verify
     the id_token signature (rs256 against the provider's jwks) and claims
     (iss, aud, exp, nonce), then find-or-create the user in the tenant and grant
     the configured default role

sso-provisioned users have an empty password hash so password login is
impossible; the idp is the sole authority. outbound http is isolated in
`http_get_json` / `http_post_form` so tests can substitute a fake idp
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from urllib import parse, request

import jwt

from app.services.authorization import ADMINISTRATION_ROLES
from app.services.net_guard import safe_urlopen
from app.storage.sso import consume_login_state, create_login_state, load_sso_configuration
from app.storage.workflow import create_platform_user, get_user_by_email, upsert_role_assignment


class SsoError(Exception):
    pass


# --- outbound http (monkeypatched in tests) -------------------------------------


def http_get_json(url: str, timeout: float = 10.0) -> dict[str, Any]:
    with safe_urlopen(url, timeout=timeout) as response:  # net_guard validates each hop
        return json.loads(response.read().decode("utf-8"))


def http_post_form(url: str, data: dict[str, str], timeout: float = 10.0) -> dict[str, Any]:
    body = parse.urlencode(data).encode("utf-8")
    req = request.Request(url, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
    with safe_urlopen(req, timeout=timeout) as response:  # net_guard validates each hop
        return json.loads(response.read().decode("utf-8"))


# --- discovery -------------------------------------------------------------------


def _normalize_issuer(issuer: str) -> str:
    parsed = parse.urlsplit(issuer.strip())
    if parsed.scheme.lower() != "https":
        raise SsoError("Issuer URL must use https")
    if not parsed.hostname:
        raise SsoError("Issuer URL must include a hostname")
    if parsed.username or parsed.password:
        raise SsoError("Issuer URL must not include credentials")
    if parsed.query or parsed.fragment:
        raise SsoError("Issuer URL must not include query or fragment")
    netloc = parsed.hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path.rstrip("/")
    return parse.urlunsplit(("https", netloc, path, "", ""))


def discover(issuer: str) -> dict[str, str]:
    """fetch the provider's openid configuration and return the endpoints we need"""
    normalized_issuer = _normalize_issuer(issuer)
    url = normalized_issuer + "/.well-known/openid-configuration"
    doc = http_get_json(url)
    try:
        return {
            "issuer": doc.get("issuer", normalized_issuer),
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
    """return (authorization url, state); the caller also sets state as a browser
    cookie and rechecks it at the callback, binding the flow to the browser that
    started it so a planted callback can't sign a victim into an attacker's account"""
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
    """exchange the code, verify the identity, return the provisioned user"""
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
            # a federated identity can't attach to another tenant's account by
            # signing in through a different org's idp
            raise SsoError("this account belongs to a different organization")
        if existing.get("status") != "active":
            raise SsoError("account is not active")
        return existing

    display_name = claims.get("name") or claims.get("preferred_username") or email
    user = create_platform_user(
        user_ref=email,
        display_name=display_name,
        email=email,
        password_hash="",  # sso-only: password login impossible
        status="active",
        platform_role=None,
        tenant_id=tenant_id,
        must_change_password=False,
    )
    # least privilege: an unconfigured default gives a read-only viewer, not a
    # reviewer with review.decide, so authenticating at the idp never grants
    # decision rights; an org admin sets default_role to grant more and can never
    # auto-grant admin
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

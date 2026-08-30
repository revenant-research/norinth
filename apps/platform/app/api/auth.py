# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import os
import secrets as pysecrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.dependencies import SESSION_COOKIE, ActorContext, current_actor, mfa_enrollment_required
from app.schemas.auth import ChangePasswordRequest, LoginRequest
from app.services import secrets as secret_store
from app.services import totp
from app.services.auth import (
    SESSION_TTL_HOURS,
    create_session,
    end_all_sessions,
    end_session,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.services.authorization import effective_permissions
from app.storage.audit import record_audit
from app.storage.login_attempts import clear_attempts, email_subject, ip_subject, is_locked, register_failure
from app.storage.mfa import (
    activate_mfa,
    clear_mfa,
    consume_challenge,
    consume_recovery_code,
    count_unused_recovery_codes,
    create_challenge,
    hash_opaque,
    load_challenge,
    record_used_counter,
    register_challenge_attempt,
    replace_recovery_codes,
    set_pending_secret,
)
from app.storage.notifications import consume_invite, peek_invite
from app.storage.organizations import load_organization
from app.storage.workflow import (
    get_user_by_email,
    load_platform_user,
    set_user_password,
    upgrade_password_hash,
)

router = APIRouter()

# a login challenge is the bridge between a verified password and a verified
# code; short-lived and burned after a handful of wrong codes
MFA_CHALLENGE_TTL_MINUTES = 5
MFA_CHALLENGE_MAX_ATTEMPTS = 5
RECOVERY_CODE_COUNT = 10
# the aad binds a stored secret to its user, so a row copied onto another
# user fails to decrypt
_MFA_AAD_PREFIX = "mfa-totp:"


def _cookie_secure(request: Request) -> bool:
    """mark the session cookie Secure whenever the deployment serves over https

    the env override wins; otherwise Secure iff the effective request scheme is
    https — directly or via a trusted proxy's x-forwarded-proto, the same signal
    the HSTS header uses. this is decided by how the request actually arrived,
    not by whether an unrelated bootstrap variable happens to be set, so a tls
    deployment is not left issuing cookies without Secure. plain-http dev stays
    non-Secure so the browser does not silently drop the cookie
    """
    override = os.getenv("NORINTH_COOKIE_SECURE")
    if override is not None:
        return override.lower() not in {"0", "false", "no"}
    scheme = request.url.scheme
    if os.getenv("NORINTH_TRUST_PROXY", "0").lower() in {"1", "true", "yes"}:
        scheme = (request.headers.get("x-forwarded-proto", scheme).split(",")[0].strip()) or scheme
    return scheme == "https"


def _set_session_cookie(request: Request, response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/",
    )


def _actor_profile(actor: ActorContext) -> dict[str, Any]:
    user = load_platform_user(actor.user_ref) or {}
    return {
        "user_ref": actor.user_ref,
        "display_name": user.get("display_name", actor.user_ref),
        "email": user.get("email"),
        "tenant_id": actor.tenant_id,
        "platform_role": actor.platform_role,
        "must_change_password": bool(user.get("must_change_password")),
        # org policy: the frontend gates the workspace behind enrollment
        "mfa_enrollment_required": mfa_enrollment_required(user),
        "permissions": effective_permissions(actor),
        "is_super_admin": actor.is_super_admin,
    }


def client_ip(request: Request) -> str | None:
    """client ip for throttling"""
    # x-forwarded-for honored only behind a declared trusted proxy
    if os.getenv("NORINTH_TRUST_PROXY", "0").lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [part.strip() for part in forwarded.split(",") if part.strip()]
            if parts:
                # read Nth from the right; leftmost entries are client-controlled
                hops = max(1, int(os.getenv("NORINTH_TRUSTED_PROXY_HOPS", "1")))
                return parts[max(0, len(parts) - hops)]
    return request.client.host if request.client else None


@router.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    # throttle per account and per source ip
    account = email_subject(payload.email)
    source = ip_subject(client_ip(request))
    if is_locked(account) or is_locked(source):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
        )
    user = get_user_by_email(payload.email)
    if user is None or user.get("status") != "active" or not verify_password(payload.password, user.get("password_hash")):
        newly_locked = [
            subject
            for subject, locked in ((account, register_failure(account)), (source, register_failure(source)))
            if locked
        ]
        # failed authentication is a security event, not just a throttle input:
        # detecting stuffing or a targeted attack needs the failures on the
        # permanent record, and the compensating notification for an operator
        # reset assumes the org can see who tried to get in
        attempted = payload.email.strip().lower()
        known_tenant = user.get("tenant_id") if user else None
        record_audit(
            actor_ref=attempted,
            action="auth.login_failed",
            tenant_id=known_tenant,
            detail={"source_ip": client_ip(request), "account_exists": user is not None},
        )
        if newly_locked:
            record_audit(
                actor_ref=attempted,
                action="auth.lockout",
                tenant_id=known_tenant,
                detail={"subjects": newly_locked, "source_ip": client_ip(request)},
            )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    clear_attempts(account)
    # rehash if kdf params are outdated, now that we have the verified plaintext.
    # upgrade_password_hash, not set_user_password: a transparent rehash must not
    # clear must_change_password, or logging in with a temporary credential would
    # silently satisfy the forced-rotation gate
    if needs_rehash(user.get("password_hash")):
        upgrade_password_hash(user["user_ref"], hash_password(payload.password))
    if user.get("mfa_enabled_at") and user.get("mfa_secret"):
        # the password step must not issue a session on an enrolled account;
        # it issues a short-lived challenge the code step redeems. nothing
        # about the account (profile, tenant, role) is revealed before the
        # second factor
        challenge = pysecrets.token_urlsafe(32)
        expires = (datetime.now(UTC) + timedelta(minutes=MFA_CHALLENGE_TTL_MINUTES)).isoformat()
        create_challenge(hash_opaque(challenge), user["user_ref"], expires)
        return {"mfa_required": True, "challenge": challenge}
    return _finish_login(request, response, user)


def _finish_login(request: Request, response: Response, user: dict[str, Any], *, mfa_method: str | None = None) -> dict[str, Any]:
    token = create_session(user["user_ref"])
    _set_session_cookie(request, response, token)
    detail = {"mfa": mfa_method} if mfa_method else None
    record_audit(actor_ref=user["user_ref"], action="auth.login", tenant_id=user.get("tenant_id"), detail=detail)
    actor = ActorContext(
        user_ref=user["user_ref"],
        tenant_id=user.get("tenant_id"),
        platform_role=user.get("platform_role"),
    )
    return {"user": _actor_profile(actor)}


class MfaVerifyRequest(BaseModel):
    challenge: str = Field(min_length=10, max_length=200)
    code: str | None = Field(default=None, min_length=6, max_length=16)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=32)


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=16)


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str | None = Field(default=None, min_length=6, max_length=16)
    recovery_code: str | None = Field(default=None, min_length=8, max_length=32)


def _decrypt_secret(user: dict[str, Any], column: str) -> str | None:
    stored = user.get(column)
    if not stored:
        return None
    try:
        return secret_store.decrypt(stored, associated_data=_MFA_AAD_PREFIX + user["user_ref"])
    except Exception:
        return None


def _new_recovery_codes(user_ref: str) -> list[str]:
    codes = [f"{pysecrets.token_hex(4)}-{pysecrets.token_hex(4)}" for _ in range(RECOVERY_CODE_COUNT)]
    replace_recovery_codes(user_ref, [hash_opaque(code) for code in codes])
    return codes


@router.post("/api/auth/mfa/verify")
def mfa_verify(payload: MfaVerifyRequest, request: Request, response: Response) -> dict[str, Any]:
    """redeem a login challenge with a totp code or a recovery code"""
    token_hash = hash_opaque(payload.challenge)
    challenge = load_challenge(token_hash)
    if challenge is None:
        raise HTTPException(status_code=401, detail="Challenge is invalid or expired; sign in again")
    user = load_platform_user(challenge["user_ref"])
    if user is None or user.get("status") != "active":
        consume_challenge(token_hash)
        raise HTTPException(status_code=403, detail="This account is not active")

    if payload.recovery_code:
        if consume_recovery_code(user["user_ref"], hash_opaque(payload.recovery_code.strip().lower())):
            consume_challenge(token_hash)
            record_audit(
                actor_ref=user["user_ref"],
                action="auth.mfa_recovery_used",
                tenant_id=user.get("tenant_id"),
                detail={"remaining": count_unused_recovery_codes(user["user_ref"])},
            )
            return _finish_login(request, response, user, mfa_method="recovery_code")
    elif payload.code:
        secret = _decrypt_secret(user, "mfa_secret")
        counter = totp.verify_code(secret, payload.code, last_counter=user.get("mfa_last_counter")) if secret else None
        if counter is not None:
            record_used_counter(user["user_ref"], counter)
            consume_challenge(token_hash)
            return _finish_login(request, response, user, mfa_method="totp")

    register_challenge_attempt(token_hash, MFA_CHALLENGE_MAX_ATTEMPTS)
    record_audit(
        actor_ref=user["user_ref"],
        action="auth.mfa_failed",
        tenant_id=user.get("tenant_id"),
        detail={"source_ip": client_ip(request)},
    )
    raise HTTPException(status_code=401, detail="That code was not accepted")


@router.get("/api/auth/mfa")
def mfa_status(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    user = load_platform_user(actor.user_ref) or {}
    enabled = bool(user.get("mfa_enabled_at") and user.get("mfa_secret"))
    return {
        "enabled": enabled,
        "enabled_at": user.get("mfa_enabled_at"),
        "recovery_codes_remaining": count_unused_recovery_codes(actor.user_ref) if enabled else 0,
    }


@router.post("/api/auth/mfa/setup")
def mfa_setup(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """stage a new totp secret; it activates only after a code proves the
    authenticator holds it"""
    user = load_platform_user(actor.user_ref) or {}
    if user.get("mfa_enabled_at") and user.get("mfa_secret"):
        raise HTTPException(status_code=409, detail="MFA is already enabled; disable it before re-enrolling")
    if not secret_store.encryption_enabled() and not os.getenv("NORINTH_ALLOW_PLAINTEXT_SECRETS"):
        raise HTTPException(
            status_code=400,
            detail="The server has no NORINTH_SECRET_KEY configured, so an MFA secret cannot be stored securely",
        )
    secret = totp.generate_secret()
    set_pending_secret(
        actor.user_ref,
        secret_store.encrypt(secret, associated_data=_MFA_AAD_PREFIX + actor.user_ref),
    )
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, actor.user_ref),
    }


@router.post("/api/auth/mfa/enable")
def mfa_enable(payload: MfaCodeRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    user = load_platform_user(actor.user_ref) or {}
    secret = _decrypt_secret(user, "mfa_pending_secret")
    if secret is None:
        raise HTTPException(status_code=400, detail="No pending MFA enrollment; call setup first")
    counter = totp.verify_code(secret, payload.code, last_counter=None)
    if counter is None:
        raise HTTPException(status_code=400, detail="That code was not accepted; check the authenticator and try again")
    activate_mfa(actor.user_ref)
    record_used_counter(actor.user_ref, counter)
    codes = _new_recovery_codes(actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="auth.mfa_enabled", tenant_id=actor.tenant_id)
    # shown exactly once; only hashes are stored
    return {"enabled": True, "recovery_codes": codes}


@router.post("/api/auth/mfa/disable")
def mfa_disable(payload: MfaDisableRequest, actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    """turning off the second factor requires both factors"""
    user = load_platform_user(actor.user_ref)
    if user is None or not verify_password(payload.password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Password is incorrect")
    proved = False
    if payload.recovery_code:
        proved = consume_recovery_code(actor.user_ref, hash_opaque(payload.recovery_code.strip().lower()))
    elif payload.code:
        secret = _decrypt_secret(user, "mfa_secret")
        counter = totp.verify_code(secret, payload.code, last_counter=user.get("mfa_last_counter")) if secret else None
        proved = counter is not None
    if not proved:
        raise HTTPException(status_code=401, detail="A valid authenticator or recovery code is required")
    clear_mfa(actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="auth.mfa_disabled", tenant_id=actor.tenant_id)
    return {"enabled": False}


@router.post("/api/auth/logout")
def logout(response: Response, norinth_session: str | None = Cookie(default=None)) -> dict[str, bool]:
    end_session(norinth_session)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/auth/me")
def me(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    return {"user": _actor_profile(actor)}


@router.post("/api/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    norinth_session: str | None = Cookie(default=None),
    actor: ActorContext = Depends(current_actor),
) -> dict[str, Any]:
    user = load_platform_user(actor.user_ref)
    if user is None or not verify_password(payload.current_password, user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current password")
    set_user_password(actor.user_ref, hash_password(payload.new_password))
    # drop all sessions (leaked token shouldn't survive), reissue for this browser
    end_all_sessions(actor.user_ref)
    token = create_session(actor.user_ref)
    _set_session_cookie(request, response, token)
    record_audit(actor_ref=actor.user_ref, action="auth.change_password", tenant_id=actor.tenant_id)
    return {"ok": True, "must_change_password": False}


@router.get("/api/auth/invite/{token}")
def invite_preview(token: str) -> dict[str, Any]:
    """invite page preview before password set"""
    invite = peek_invite(token)
    if invite is None:
        raise HTTPException(status_code=404, detail="This invite link is invalid, expired, or already used")
    user = load_platform_user(invite["user_ref"]) or {}
    organization = load_organization(invite["tenant_id"]) or {}
    return {"email": invite["user_ref"], "display_name": user.get("display_name"), "organization": organization.get("name") or invite["tenant_id"]}


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    password: str = Field(min_length=12, max_length=256)


@router.post("/api/auth/accept-invite")
def accept_invite(payload: AcceptInviteRequest, request: Request, response: Response) -> dict[str, Any]:
    invite = consume_invite(payload.token)
    if invite is None:
        raise HTTPException(status_code=404, detail="This invite link is invalid, expired, or already used")
    user = load_platform_user(invite["user_ref"])
    if user is None or user.get("status") != "active":
        raise HTTPException(status_code=403, detail="This account is not active")
    set_user_password(invite["user_ref"], hash_password(payload.password))  # also clears must_change_password
    end_all_sessions(invite["user_ref"])
    token = create_session(invite["user_ref"])
    _set_session_cookie(request, response, token)
    record_audit(actor_ref=invite["user_ref"], action="auth.accept_invite", tenant_id=invite["tenant_id"], target_type="user", target_id=invite["user_ref"])
    actor = ActorContext(user_ref=invite["user_ref"], tenant_id=invite["tenant_id"], platform_role=None)
    return {"user": _actor_profile(actor)}

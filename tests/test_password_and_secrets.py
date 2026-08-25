"""password kdf hardening and fail-closed secret storage"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_verify_rejects_non_allowlisted_algorithm():
    from app.services.auth import verify_password

    # a tampered db row naming a weak/unknown kdf must never be executed
    forged = "pbkdf2_md5$1$00$deadbeef"
    assert verify_password("whatever", forged) is False


def test_needs_rehash_flags_weaker_hashes():
    from app.services import auth

    weak = f"pbkdf2_sha256${auth._PBKDF2_ITERATIONS - 1}$00$00"
    current = auth.hash_password("correct horse battery staple")
    assert auth.needs_rehash(weak) is True
    assert auth.needs_rehash(current) is False
    assert auth.needs_rehash(None) is True


def test_hash_roundtrip_uses_current_params():
    from app.services import auth

    stored = auth.hash_password("s3cret-password")
    assert stored.startswith(f"pbkdf2_sha256${auth._PBKDF2_ITERATIONS}$")
    assert auth.verify_password("s3cret-password", stored) is True
    assert auth.verify_password("wrong", stored) is False


def test_login_upgrades_a_weak_hash(client):
    # seed a user whose stored hash uses far fewer iterations than current
    import hashlib

    from app.services import auth
    from app.storage.workflow import create_platform_user, load_platform_user

    salt = b"0123456789abcdef"
    weak_rounds = 1000
    derived = hashlib.pbkdf2_hmac("sha256", b"pw-123456", salt, weak_rounds)
    weak_hash = f"pbkdf2_sha256${weak_rounds}${salt.hex()}${derived.hex()}"
    create_platform_user(
        user_ref="weak@acme.test",
        display_name="Weak",
        email="weak@acme.test",
        password_hash=weak_hash,
        status="active",
        platform_role=None,
        tenant_id="acme",
        must_change_password=False,
    )
    assert auth.needs_rehash(weak_hash)

    resp = client.post("/api/auth/login", json={"email": "weak@acme.test", "password": "pw-123456"})
    assert resp.status_code == 200, resp.text

    upgraded = load_platform_user("weak@acme.test")["password_hash"]
    assert upgraded != weak_hash
    assert not auth.needs_rehash(upgraded)
    assert auth.verify_password("pw-123456", upgraded)


def test_encrypt_fails_closed_without_a_key(monkeypatch):
    from app.services.secrets import SecretKeyMissing, encrypt

    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("NORINTH_ALLOW_PLAINTEXT_SECRETS", raising=False)
    with pytest.raises(SecretKeyMissing):
        encrypt("a-secret")


def test_encrypt_allows_plaintext_only_with_explicit_optin(monkeypatch):
    from app.services.secrets import encrypt

    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.setenv("NORINTH_ALLOW_PLAINTEXT_SECRETS", "1")
    assert encrypt("a-secret") == "a-secret"


def test_password_floor_is_consistent_across_set_paths(super_admin_client):
    """the change-password path enforces the same minimum as signup

    the initial-set floor was 12 while change-password allowed 8, so the strong
    minimum could be rotated away immediately. every path that sets a password
    now uses one floor
    """
    from app.main import app
    from app.services.auth import MIN_PASSWORD_LENGTH
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

    assert MIN_PASSWORD_LENGTH == 12

    # creating an org admin below the floor is refused
    short = super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "short-pw-1"},
    )
    assert short.status_code == 422, short.text

    # a valid org, then a change-password to a sub-floor value is refused too
    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-strong-pw-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-strong-pw-1")
        weak = org.post("/api/auth/change-password",
                        json={"current_password": "oa-strong-pw-1-rotated-1", "new_password": "eleven-char"})
        assert weak.status_code == 422, weak.text
        ok = org.post("/api/auth/change-password",
                      json={"current_password": "oa-strong-pw-1-rotated-1", "new_password": "twelve-chars-1"})
        assert ok.status_code == 200, ok.text

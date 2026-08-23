"""Tests for application-layer encryption of stored secrets."""

from __future__ import annotations

import base64
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def test_roundtrip_and_tenant_binding(monkeypatch):
    monkeypatch.setenv("NORINTH_SECRET_KEY", _key())
    from app.services.secrets import SecretKeyMissing, decrypt, encrypt, is_encrypted

    stored = encrypt("s3cret", associated_data="acme")
    assert is_encrypted(stored)
    assert "s3cret" not in stored
    assert decrypt(stored, associated_data="acme") == "s3cret"
    # Bound to the tenant: the same ciphertext cannot be read under another tenant.
    with pytest.raises(SecretKeyMissing):
        decrypt(stored, associated_data="beta")


def test_wrong_key_fails_closed(monkeypatch):
    from app.services.secrets import SecretKeyMissing, decrypt, encrypt

    monkeypatch.setenv("NORINTH_SECRET_KEY", _key())
    stored = encrypt("s3cret")
    monkeypatch.setenv("NORINTH_SECRET_KEY", _key())  # rotate to an unrelated key
    with pytest.raises(SecretKeyMissing):
        decrypt(stored)


def test_legacy_plaintext_passes_through(monkeypatch):
    monkeypatch.setenv("NORINTH_SECRET_KEY", _key())
    from app.services.secrets import decrypt

    assert decrypt("plain-old-value") == "plain-old-value"


def test_invalid_key_is_rejected(monkeypatch):
    monkeypatch.setenv("NORINTH_SECRET_KEY", "too-short")
    from app.services.secrets import SecretKeyMissing, master_key

    with pytest.raises(SecretKeyMissing):
        master_key()


def test_sso_client_secret_is_ciphertext_at_rest(super_admin_client, monkeypatch):
    monkeypatch.setenv("NORINTH_SECRET_KEY", _key())
    import app.services.sso as sso_service
    from app.main import app
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    monkeypatch.setattr(
        sso_service,
        "http_get_json",
        lambda url, timeout=10.0: {
            "issuer": "https://idp.example.test",
            "authorization_endpoint": "https://idp.example.test/authorize",
            "token_endpoint": "https://idp.example.test/token",
            "jwks_uri": "https://idp.example.test/jwks",
        },
    )
    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "acme", "admin_email": "oa@acme.test", "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        resp = org.put("/api/org/sso", json={"issuer": "https://idp.example.test", "client_id": "c", "client_secret": "super-secret-value"})
        assert resp.status_code == 200, resp.text

    with connect() as connection:
        row = connection.execute("SELECT client_secret FROM sso_configurations WHERE tenant_id = 'acme'").fetchone()
    assert row["client_secret"].startswith("enc:v1:")
    assert "super-secret-value" not in row["client_secret"]

    # The service still reads the plaintext through the storage layer.
    from app.storage.sso import load_sso_configuration

    assert load_sso_configuration("acme")["client_secret"] == "super-secret-value"

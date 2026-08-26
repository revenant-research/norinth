"""application-layer encryption of stored secrets"""

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
    # bound to the tenant: same ciphertext can't be read under another tenant
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


def test_rotation_keeps_old_values_readable_and_writes_under_the_new_key(monkeypatch):
    """add a new primary, keep the old key in the ring: old ciphertext still
    decrypts, new writes use the new key"""
    import importlib

    old, new = _key(), _key()
    monkeypatch.setenv("NORINTH_SECRET_KEY", old)
    monkeypatch.delenv("NORINTH_SECRET_KEYS", raising=False)
    monkeypatch.delenv("NORINTH_SECRET_PRIMARY", raising=False)
    secrets = importlib.import_module("app.services.secrets")

    before = secrets.encrypt("s3cret", associated_data="acme")
    assert before.startswith("enc:v2:legacy:")

    # rotate: legacy stays in the ring for decryption, 2026a becomes primary
    import json
    monkeypatch.setenv("NORINTH_SECRET_KEYS", json.dumps({"2026a": new}))
    monkeypatch.setenv("NORINTH_SECRET_PRIMARY", "2026a")

    # the value written under the old key still decrypts
    assert secrets.decrypt(before, associated_data="acme") == "s3cret"
    # new writes are under the new primary key
    after = secrets.encrypt("s3cret", associated_data="acme")
    assert after.startswith("enc:v2:2026a:")
    assert secrets.decrypt(after, associated_data="acme") == "s3cret"


def test_v1_ciphertext_still_decrypts_via_the_ring(monkeypatch):
    """a value in the pre-keyring enc:v1 format is decrypted by trying ring keys"""
    import base64 as _b64
    import os as _os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_b64 = _key()
    key = _b64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    nonce = _os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, b"s3cret", b"acme")
    legacy_value = "enc:v1:" + _b64.urlsafe_b64encode(nonce).decode() + ":" + _b64.urlsafe_b64encode(ct).decode()

    # this key lives in the ring under a non-legacy id; v1 has no id so decrypt
    # must find it by trying each key
    import json
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.setenv("NORINTH_SECRET_KEYS", json.dumps({"2026a": key_b64}))
    monkeypatch.setenv("NORINTH_SECRET_PRIMARY", "2026a")
    from app.services.secrets import decrypt

    assert decrypt(legacy_value, associated_data="acme") == "s3cret"


def test_missing_key_id_in_ring_fails_closed(monkeypatch):
    """a value encrypted under a key that is no longer in the ring is refused"""
    import json

    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.setenv("NORINTH_SECRET_KEYS", json.dumps({"2026a": _key()}))
    monkeypatch.setenv("NORINTH_SECRET_PRIMARY", "2026a")
    from app.services.secrets import SecretKeyMissing, decrypt, encrypt

    stored = encrypt("s3cret")
    assert stored.startswith("enc:v2:2026a:")
    # drop 2026a, configure only a different key
    monkeypatch.setenv("NORINTH_SECRET_KEYS", json.dumps({"2027a": _key()}))
    monkeypatch.setenv("NORINTH_SECRET_PRIMARY", "2027a")
    with pytest.raises(SecretKeyMissing):
        decrypt(stored)


def test_multi_key_ring_requires_a_named_primary(monkeypatch):
    import json

    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.setenv("NORINTH_SECRET_KEYS", json.dumps({"2026a": _key()}))
    monkeypatch.delenv("NORINTH_SECRET_PRIMARY", raising=False)
    from app.services.secrets import SecretKeyMissing, encrypt

    with pytest.raises(SecretKeyMissing):
        encrypt("s3cret")


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
    assert row["client_secret"].startswith("enc:v2:")
    assert "super-secret-value" not in row["client_secret"]

    # service still reads the plaintext through the storage layer
    from app.storage.sso import load_sso_configuration

    assert load_sso_configuration("acme")["client_secret"] == "super-secret-value"

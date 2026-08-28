"""application-layer encryption for stored secrets, with key rotation

secrets the platform must keep recoverable (a tenant's OIDC client secret, a
webhook signing secret) are encrypted at rest with AES-256-GCM so a database dump
or backup does not yield usable credentials.

key material — a keyring of one or more 32-byte keys, each with a short id:
  NORINTH_SECRET_KEYS     JSON object {"<id>": "<base64 32-byte key>", ...}
  NORINTH_SECRET_PRIMARY  the id in the ring used to encrypt NEW values
  NORINTH_SECRET_KEY      legacy single key; treated as a ring with one key
                          whose id is "legacy" (primary when no ring is given)

Rotation: add a new key to NORINTH_SECRET_KEYS, point NORINTH_SECRET_PRIMARY at
it, and keep the previous key in the ring so existing values still decrypt. New
writes use the new key; old values are re-encrypted under the primary the next
time they are written. Once nothing references the old key, drop it from the ring.

stored value format: ``enc:v2:<key_id>:<base64 nonce>:<base64 ciphertext+tag>``.
Legacy ``enc:v1:<nonce>:<ct>`` values carry no key id and are decrypted by trying
each key in the ring. Values with no prefix are legacy plaintext, re-encrypted on
next write. With no key configured in dev, values are stored as-is (with a
warning); production must configure a key.
"""

from __future__ import annotations

import base64
import json
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("norinth.secrets")

_PREFIX_V2 = "enc:v2:"
_PREFIX_V1 = "enc:v1:"
_LEGACY_KEY_ID = "legacy"


class SecretKeyMissing(RuntimeError):
    pass


def _decode_key(raw: str, label: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as error:
        raise SecretKeyMissing(f"{label} is not valid base64") from error
    if len(key) != 32:
        raise SecretKeyMissing(f"{label} must decode to exactly 32 bytes")
    return key


def keyring() -> dict[str, bytes]:
    """all keys available for decryption, id -> 32 raw bytes

    a legacy NORINTH_SECRET_KEY, if set, is included under the id "legacy" so
    values written before the ring existed still decrypt
    """
    ring: dict[str, bytes] = {}
    legacy = os.getenv("NORINTH_SECRET_KEY")
    if legacy:
        ring[_LEGACY_KEY_ID] = _decode_key(legacy, "NORINTH_SECRET_KEY")
    raw = os.getenv("NORINTH_SECRET_KEYS")
    if raw:
        try:
            entries = json.loads(raw)
        except Exception as error:
            raise SecretKeyMissing("NORINTH_SECRET_KEYS is not valid JSON") from error
        if not isinstance(entries, dict) or not entries:
            raise SecretKeyMissing("NORINTH_SECRET_KEYS must be a non-empty JSON object of {id: base64 key}")
        for kid, value in entries.items():
            if not isinstance(kid, str) or ":" in kid or not kid:
                raise SecretKeyMissing("secret key ids must be non-empty strings without ':'")
            ring[kid] = _decode_key(value, f"NORINTH_SECRET_KEYS['{kid}']")
    return ring


def primary_key_id() -> str | None:
    """id of the key used to encrypt new values, or None if no key is configured"""
    ring = keyring()
    explicit = os.getenv("NORINTH_SECRET_PRIMARY")
    if explicit:
        if explicit not in ring:
            raise SecretKeyMissing(f"NORINTH_SECRET_PRIMARY '{explicit}' is not present in the keyring")
        return explicit
    # a multi-key ring must name its primary; a lone legacy key is its own primary
    if os.getenv("NORINTH_SECRET_KEYS"):
        raise SecretKeyMissing("NORINTH_SECRET_KEYS is set; also set NORINTH_SECRET_PRIMARY to name the active key")
    if _LEGACY_KEY_ID in ring:
        return _LEGACY_KEY_ID
    return None


def master_key() -> bytes | None:
    """the primary key's bytes, or None when no key is configured

    kept for callers that only need to know whether encryption is available (and
    to fail fast on a malformed key at startup)
    """
    primary = primary_key_id()
    if primary is None:
        return None
    return keyring()[primary]


def encryption_enabled() -> bool:
    return master_key() is not None


def _plaintext_allowed() -> bool:
    return os.getenv("NORINTH_ALLOW_PLAINTEXT_SECRETS", "0").lower() in {"1", "true", "yes"}


def _aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, associated_data: str) -> str:
    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ct_b64)
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data.encode("utf-8") or None).decode("utf-8")


def _require_binding(associated_data: str) -> None:
    """aad is the context binding that stops a ciphertext being replayed onto
    another row (a tenant's sso secret pasted into another tenant's config).
    an empty string silently became no-AAD, which is the binding vanishing
    exactly when a caller's tenant id happened to be blank — fail instead"""
    if not associated_data:
        raise ValueError(
            "associated_data must be a non-empty context binding (e.g. the tenant id or record key)"
        )


def encrypt(value: str, *, associated_data: str) -> str:
    """encrypt a secret for storage under the primary key

    fails closed: without a configured key it raises rather than storing
    plaintext; opt into plaintext with NORINTH_ALLOW_PLAINTEXT_SECRETS=1
    """
    _require_binding(associated_data)
    primary = primary_key_id()
    if primary is None:
        if _plaintext_allowed():
            logger.warning(
                "No secret key is configured; storing a secret unencrypted "
                "(NORINTH_ALLOW_PLAINTEXT_SECRETS=1, development only)"
            )
            return value
        raise SecretKeyMissing(
            "Refusing to store a secret without encryption. Set NORINTH_SECRET_KEY (or "
            "NORINTH_SECRET_KEYS + NORINTH_SECRET_PRIMARY), or set "
            "NORINTH_ALLOW_PLAINTEXT_SECRETS=1 to allow plaintext (development only)."
        )
    key = keyring()[primary]
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), associated_data.encode("utf-8") or None)
    return (
        f"{_PREFIX_V2}{primary}:"
        + base64.urlsafe_b64encode(nonce).decode()
        + ":"
        + base64.urlsafe_b64encode(ciphertext).decode()
    )


def decrypt(stored: str, *, associated_data: str) -> str:
    """decrypt a stored secret; legacy plaintext passes through"""
    _require_binding(associated_data)
    if stored.startswith(_PREFIX_V2):
        ring = keyring()
        kid, _, tail = stored[len(_PREFIX_V2):].partition(":")
        nonce_b64, _, ct_b64 = tail.partition(":")
        key = ring.get(kid)
        if key is None:
            raise SecretKeyMissing(
                f"a stored secret was encrypted under key '{kid}', which is not in the configured keyring"
            )
        try:
            return _aesgcm_decrypt(key, nonce_b64, ct_b64, associated_data)
        except Exception as error:
            raise SecretKeyMissing("stored secret could not be decrypted (wrong key or corrupted value)") from error
    if stored.startswith(_PREFIX_V1):
        ring = keyring()
        if not ring:
            raise SecretKeyMissing("a stored secret is encrypted but no secret key is configured")
        _, _, rest = stored.partition(_PREFIX_V1)
        nonce_b64, _, ct_b64 = rest.partition(":")
        # v1 values carry no key id; try each key until one authenticates
        for key in ring.values():
            try:
                return _aesgcm_decrypt(key, nonce_b64, ct_b64, associated_data)
            except Exception:
                continue
        raise SecretKeyMissing("stored secret could not be decrypted (wrong key or corrupted value)")
    return stored


def is_encrypted(stored: str) -> bool:
    return stored.startswith(_PREFIX_V2) or stored.startswith(_PREFIX_V1)

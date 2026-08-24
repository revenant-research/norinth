"""application-layer encryption for stored secrets (envelope-ready)

secrets the platform must keep recoverable (today: each tenant's oidc client
secret) are encrypted at rest with aes-256-gcm under a master key from the env,
so a db dump or backup does not yield usable credentials

key material:
  NORINTH_SECRET_KEY   base64 (urlsafe) 32-byte key. generate with
                       `python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"`
                       in production inject from a kms/secret manager; envelope-
                       ready: swap `master_key()` for a kms data key

stored value format: ``enc:v1:<base64 nonce>:<base64 ciphertext+tag>``. values
without the prefix are legacy plaintext, re-encrypted next write. with no key in
dev, values are stored as-is (with a warning); production must set the key
"""

from __future__ import annotations

import base64
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("norinth.secrets")

_PREFIX = "enc:v1:"


class SecretKeyMissing(RuntimeError):
    pass


def master_key() -> bytes | None:
    raw = os.getenv("NORINTH_SECRET_KEY")
    if not raw:
        return None
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as error:
        raise SecretKeyMissing("NORINTH_SECRET_KEY is not valid base64") from error
    if len(key) != 32:
        raise SecretKeyMissing("NORINTH_SECRET_KEY must decode to exactly 32 bytes")
    return key


def encryption_enabled() -> bool:
    return master_key() is not None


def _plaintext_allowed() -> bool:
    return os.getenv("NORINTH_ALLOW_PLAINTEXT_SECRETS", "0").lower() in {"1", "true", "yes"}


def encrypt(value: str, *, associated_data: str = "") -> str:
    """encrypt a secret for storage

    fails closed: without NORINTH_SECRET_KEY it raises rather than storing
    plaintext; opt into plaintext with NORINTH_ALLOW_PLAINTEXT_SECRETS=1
    """
    key = master_key()
    if key is None:
        if _plaintext_allowed():
            logger.warning(
                "NORINTH_SECRET_KEY is not set; storing a secret unencrypted "
                "(NORINTH_ALLOW_PLAINTEXT_SECRETS=1, development only)"
            )
            return value
        raise SecretKeyMissing(
            "Refusing to store a secret without encryption. Set NORINTH_SECRET_KEY, "
            "or set NORINTH_ALLOW_PLAINTEXT_SECRETS=1 to allow plaintext (development only)."
        )
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), associated_data.encode("utf-8") or None)
    return _PREFIX + base64.urlsafe_b64encode(nonce).decode() + ":" + base64.urlsafe_b64encode(ciphertext).decode()


def decrypt(stored: str, *, associated_data: str = "") -> str:
    """decrypt a stored secret; legacy plaintext passes through"""
    if not stored.startswith(_PREFIX):
        return stored
    key = master_key()
    if key is None:
        raise SecretKeyMissing("a stored secret is encrypted but NORINTH_SECRET_KEY is not configured")
    try:
        _, _, rest = stored.partition(_PREFIX)
        nonce_b64, _, ct_b64 = rest.partition(":")
        nonce = base64.urlsafe_b64decode(nonce_b64)
        ciphertext = base64.urlsafe_b64decode(ct_b64)
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data.encode("utf-8") or None).decode("utf-8")
    except SecretKeyMissing:
        raise
    except Exception as error:
        raise SecretKeyMissing("stored secret could not be decrypted (wrong key or corrupted value)") from error


def is_encrypted(stored: str) -> bool:
    return stored.startswith(_PREFIX)

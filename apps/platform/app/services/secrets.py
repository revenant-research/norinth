"""Application-layer encryption for stored secrets (envelope-ready).

Secrets the platform must keep in recoverable form (today: each tenant's OIDC
client secret) are encrypted at rest with AES-256-GCM under a master key
supplied by the environment, so a database dump or backup does not yield
usable credentials. Enterprise buyers expect this ("encryption at rest / KMS /
BYOK", GTM §6).

Key material:
  NORINTH_SECRET_KEY   base64 (urlsafe) 32-byte key. Generate with
                       `python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"`.
                       In production this should be injected from a KMS/secret
                       manager (AWS KMS / Vault / Azure Key Vault) -- the design
                       is envelope-ready: swap `master_key()` for a KMS data key.

Format of stored values: ``enc:v1:<base64 nonce>:<base64 ciphertext+tag>``.
Values without the prefix are treated as legacy plaintext and transparently
re-encrypted the next time they are written. When no key is configured in
development, values are stored as-is (with a warning) so the quickstart works;
production deployments must set the key (see SECURITY.md).
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


def encrypt(value: str, *, associated_data: str = "") -> str:
    """Encrypt a secret for storage. Returns the value unchanged (with a
    warning) when no master key is configured."""
    key = master_key()
    if key is None:
        logger.warning("NORINTH_SECRET_KEY is not set; storing a secret unencrypted (development only)")
        return value
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), associated_data.encode("utf-8") or None)
    return _PREFIX + base64.urlsafe_b64encode(nonce).decode() + ":" + base64.urlsafe_b64encode(ciphertext).decode()


def decrypt(stored: str, *, associated_data: str = "") -> str:
    """Decrypt a stored secret. Legacy plaintext values pass through."""
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

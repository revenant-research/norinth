"""the AAD context binding on stored secrets can never silently vanish

encrypt/decrypt defaulted associated_data to "" and AESGCM treated the empty
string as no AAD at all — so the binding that stops a ciphertext being
replayed onto another row disappeared exactly when a caller's tenant id
happened to be blank. an empty binding is now an error, not a downgrade.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_empty_binding_is_refused(fresh_db):
    from app.services import secrets

    with pytest.raises(ValueError, match="associated_data"):
        secrets.encrypt("value", associated_data="")
    with pytest.raises(ValueError, match="associated_data"):
        secrets.decrypt("enc:v2:x:y:z", associated_data="")


def test_binding_is_enforced_across_contexts(fresh_db):
    """a ciphertext bound to one tenant must not decrypt under another"""
    from app.services import secrets

    stored = secrets.encrypt("client-secret", associated_data="tenant-a")
    assert secrets.decrypt(stored, associated_data="tenant-a") == "client-secret"
    with pytest.raises(secrets.SecretKeyMissing):
        secrets.decrypt(stored, associated_data="tenant-b")


def test_binding_is_keyword_only_and_required(fresh_db):
    from app.services import secrets

    with pytest.raises(TypeError):
        secrets.encrypt("value")  # type: ignore[call-arg]

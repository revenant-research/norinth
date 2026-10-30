"""a login attempt costs the same whether or not the email names an account

the password verifier runs 600k pbkdf2 rounds. skipping it for an unknown or
inactive account made the response measurably faster, so response time told
an attacker which emails exist
"""

from __future__ import annotations


def test_unknown_and_inactive_accounts_still_pay_for_a_verification(client, monkeypatch):
    from app.api import auth as auth_api

    spent: list[str] = []
    monkeypatch.setattr(auth_api, "spend_verification_time", lambda: spent.append("decoy"))

    refused = client.post("/api/auth/login", json={"email": "nobody@acme.test", "password": "whatever-password-1"})
    assert refused.status_code == 401
    assert spent == ["decoy"]


def test_a_known_active_account_is_verified_for_real(client, monkeypatch):
    from app.api import auth as auth_api

    spent: list[str] = []
    monkeypatch.setattr(auth_api, "spend_verification_time", lambda: spent.append("decoy"))

    refused = client.post("/api/auth/login", json={"email": "admin@norinth.local", "password": "wrong-password-1"})
    assert refused.status_code == 401
    assert spent == []


def test_the_decoy_verification_runs_the_real_verifier():
    from app.services import auth

    auth._decoy_hash.cache_clear()
    assert auth._decoy_hash().startswith("pbkdf2_")
    assert auth._decoy_hash() == auth._decoy_hash()  # computed once, reused
    auth.spend_verification_time()  # must not raise

"""server-side auth enforcement and session hardening"""

from __future__ import annotations

DEFAULT_ADMIN = {"email": "admin@norinth.local", "password": "norinth-admin"}


def test_must_change_password_blocks_api_until_changed(client):
    # log in as bootstrap admin (must_change_password) without rotating the
    # password, admin endpoints must be blocked (403)
    login = client.post("/api/auth/login", json=DEFAULT_ADMIN)
    assert login.status_code == 200
    assert login.json()["user"]["must_change_password"] is True

    blocked = client.get("/api/admin/organizations")
    assert blocked.status_code == 403
    assert "Password change required" in blocked.json()["detail"]

    # /me and change-password stay reachable
    assert client.get("/api/auth/me").status_code == 200

    changed = client.post(
        "/api/auth/change-password",
        json={"current_password": "norinth-admin", "new_password": "a-brand-new-pw-9"},
    )
    assert changed.status_code == 200, changed.text

    # after the change and cookie rotation the api is reachable
    assert client.get("/api/admin/organizations").status_code == 200


def test_change_password_rejects_same_password(client):
    client.post("/api/auth/login", json=DEFAULT_ADMIN)
    resp = client.post(
        "/api/auth/change-password",
        json={"current_password": "norinth-admin", "new_password": "norinth-admin"},
    )
    assert resp.status_code == 400


def test_session_tokens_are_stored_hashed(client):
    resp = client.post("/api/auth/login", json=DEFAULT_ADMIN)
    assert resp.status_code == 200
    cookie = client.cookies.get("norinth_session")
    assert cookie

    from app.storage.raw_events import connect

    with connect() as connection:
        rows = connection.execute("SELECT token FROM sessions").fetchall()
    stored = {row["token"] for row in rows}
    # plaintext cookie must never be in storage, only its hash
    assert cookie not in stored
    assert all(len(tok) == 64 for tok in stored)  # sha256 hex digests


def test_password_change_revokes_other_sessions(client):
    # two independent logins for the same admin, two sessions
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as other:
        other.post("/api/auth/login", json=DEFAULT_ADMIN)
        # `other` is authenticated, subject to the password-change gate but /me works
        assert other.get("/api/auth/me").status_code == 200

        client.post("/api/auth/login", json=DEFAULT_ADMIN)
        client.post(
            "/api/auth/change-password",
            json={"current_password": "norinth-admin", "new_password": "rotated-pw-1234"},
        )

        # other session's token revoked by the password change
        assert other.get("/api/auth/me").status_code == 401

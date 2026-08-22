"""Regression tests for login lockout (H-6) and CSRF defense-in-depth (H-8)."""

from __future__ import annotations

BAD = {"email": "admin@norinth.local", "password": "wrong-password"}
GOOD = {"email": "admin@norinth.local", "password": "norinth-admin"}


def test_login_locks_after_repeated_failures(client):
    # Default threshold is 5 failures.
    for _ in range(5):
        assert client.post("/api/auth/login", json=BAD).status_code == 401
    # Now locked: further attempts (even with the correct password) are throttled.
    locked = client.post("/api/auth/login", json=GOOD)
    assert locked.status_code == 429
    assert "Too many failed login attempts" in locked.json()["detail"]


def test_successful_login_clears_failures(client):
    # A few failures, then a success, then failures again should not immediately
    # lock (the counter was cleared on success).
    for _ in range(3):
        client.post("/api/auth/login", json=BAD)
    assert client.post("/api/auth/login", json=GOOD).status_code == 200
    # Fresh window after the successful login.
    assert client.post("/api/auth/login", json=BAD).status_code == 401


def test_csrf_rejects_cross_origin_mutation(client):
    resp = client.post(
        "/api/auth/login",
        json=GOOD,
        headers={"Origin": "http://evil.example.com"},
    )
    assert resp.status_code == 403
    assert "Cross-origin" in resp.json()["detail"]


def test_csrf_allows_same_origin_mutation(client):
    resp = client.post(
        "/api/auth/login",
        json=GOOD,
        headers={"Origin": "http://testserver"},
    )
    assert resp.status_code == 200


def test_csrf_allows_requests_without_origin(client):
    # Non-browser clients (no Origin header) are unaffected — they don't carry a
    # victim's ambient cookies, so they are not a CSRF vector.
    resp = client.post("/api/auth/login", json=GOOD)
    assert resp.status_code == 200

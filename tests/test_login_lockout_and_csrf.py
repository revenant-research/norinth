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


def test_password_spraying_across_accounts_trips_ip_throttle(client, monkeypatch):
    # Lower the IP threshold for the test; per-account threshold (5) is never hit
    # because every attempt targets a different email.
    import app.storage.login_attempts as la

    monkeypatch.setattr(la, "IP_THRESHOLD", 8)
    for i in range(8):
        resp = client.post("/api/auth/login", json={"email": f"user{i}@acme.test", "password": "Spring2026!"})
        assert resp.status_code == 401
    # The source IP is now throttled even for a brand-new, never-attempted email.
    resp = client.post("/api/auth/login", json={"email": "fresh@acme.test", "password": "whatever"})
    assert resp.status_code == 429


def test_forwarded_for_is_ignored_unless_proxy_trusted(client, monkeypatch):
    import app.storage.login_attempts as la

    monkeypatch.setattr(la, "IP_THRESHOLD", 3)
    monkeypatch.delenv("NORINTH_TRUST_PROXY", raising=False)
    # Attacker rotates X-Forwarded-For to dodge the IP throttle: must not work,
    # because the header is untrusted by default.
    for i in range(3):
        client.post("/api/auth/login", json={"email": f"u{i}@x.test", "password": "bad"}, headers={"X-Forwarded-For": f"10.0.0.{i}"})
    resp = client.post("/api/auth/login", json={"email": "u9@x.test", "password": "bad"}, headers={"X-Forwarded-For": "10.0.0.99"})
    assert resp.status_code == 429


def test_forwarded_for_is_used_when_proxy_trusted(client, monkeypatch):
    import app.storage.login_attempts as la

    monkeypatch.setattr(la, "IP_THRESHOLD", 3)
    monkeypatch.setenv("NORINTH_TRUST_PROXY", "1")
    # Behind a trusted proxy, distinct real client IPs are throttled independently.
    for i in range(3):
        client.post("/api/auth/login", json={"email": f"u{i}@x.test", "password": "bad"}, headers={"X-Forwarded-For": "203.0.113.7"})
    blocked = client.post("/api/auth/login", json={"email": "u9@x.test", "password": "bad"}, headers={"X-Forwarded-For": "203.0.113.7"})
    assert blocked.status_code == 429
    other = client.post("/api/auth/login", json={"email": "u9@x.test", "password": "bad"}, headers={"X-Forwarded-For": "203.0.113.8"})
    assert other.status_code == 401  # different client, not throttled


def test_csrf_accepts_https_origin_behind_trusted_proxy(client, monkeypatch):
    """Behind a TLS-terminating proxy (NORINTH_TRUST_PROXY=1) a browser's https
    Origin must be accepted even though the request scheme is http (finding H2)."""
    monkeypatch.setenv("NORINTH_TRUST_PROXY", "1")
    headers = {"Origin": "https://norinth.example.com", "Host": "internal:8001",
               "X-Forwarded-Proto": "https", "X-Forwarded-Host": "norinth.example.com"}
    # A mutating cookie-route call: without the fix this 403s before auth.
    resp = client.post("/api/auth/login", json={"email": "x@y.z", "password": "nope"}, headers=headers)
    assert resp.status_code != 403  # reaches auth (401 invalid creds), not CSRF-rejected

    # A genuinely cross-site Origin is still rejected.
    bad = client.post("/api/auth/login", json={"email": "x@y.z", "password": "nope"},
                      headers={"Origin": "https://evil.example", "Host": "internal:8001",
                               "X-Forwarded-Proto": "https", "X-Forwarded-Host": "norinth.example.com"})
    assert bad.status_code == 403

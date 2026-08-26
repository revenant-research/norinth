"""login lockout and csrf origin checks"""

from __future__ import annotations

BAD = {"email": "admin@norinth.local", "password": "wrong-password"}
GOOD = {"email": "admin@norinth.local", "password": "norinth-admin"}


def test_login_locks_after_repeated_failures(client):
    # default threshold is 5 failures
    for _ in range(5):
        assert client.post("/api/auth/login", json=BAD).status_code == 401
    # locked now: even the correct password is throttled
    locked = client.post("/api/auth/login", json=GOOD)
    assert locked.status_code == 429
    assert "Too many failed login attempts" in locked.json()["detail"]


def test_successful_login_clears_failures(client):
    # success clears the counter, so failures after it don't immediately lock
    for _ in range(3):
        client.post("/api/auth/login", json=BAD)
    assert client.post("/api/auth/login", json=GOOD).status_code == 200
    # fresh window after the successful login
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
    # no origin header means non-browser client with no ambient cookies, not a csrf vector
    resp = client.post("/api/auth/login", json=GOOD)
    assert resp.status_code == 200


def test_password_spraying_across_accounts_trips_ip_throttle(client, monkeypatch):
    # lower ip threshold for the test; per-account threshold (5) never hit since each attempt is a different email
    import app.storage.login_attempts as la

    monkeypatch.setattr(la, "IP_THRESHOLD", 8)
    for i in range(8):
        resp = client.post("/api/auth/login", json={"email": f"user{i}@acme.test", "password": "Spring2026!"})
        assert resp.status_code == 401
    # source ip throttled even for a brand-new email
    resp = client.post("/api/auth/login", json={"email": "fresh@acme.test", "password": "whatever"})
    assert resp.status_code == 429


def test_forwarded_for_is_ignored_unless_proxy_trusted(client, monkeypatch):
    import app.storage.login_attempts as la

    monkeypatch.setattr(la, "IP_THRESHOLD", 3)
    monkeypatch.delenv("NORINTH_TRUST_PROXY", raising=False)
    # rotating x-forwarded-for must not dodge the ip throttle; header untrusted by default
    for i in range(3):
        client.post("/api/auth/login", json={"email": f"u{i}@x.test", "password": "bad"}, headers={"X-Forwarded-For": f"10.0.0.{i}"})
    resp = client.post("/api/auth/login", json={"email": "u9@x.test", "password": "bad"}, headers={"X-Forwarded-For": "10.0.0.99"})
    assert resp.status_code == 429


def test_forwarded_for_is_used_when_proxy_trusted(client, monkeypatch):
    import app.storage.login_attempts as la

    monkeypatch.setattr(la, "IP_THRESHOLD", 3)
    monkeypatch.setenv("NORINTH_TRUST_PROXY", "1")
    # behind a trusted proxy distinct real client ips are throttled independently
    for i in range(3):
        client.post("/api/auth/login", json={"email": f"u{i}@x.test", "password": "bad"}, headers={"X-Forwarded-For": "203.0.113.7"})
    blocked = client.post("/api/auth/login", json={"email": "u9@x.test", "password": "bad"}, headers={"X-Forwarded-For": "203.0.113.7"})
    assert blocked.status_code == 429
    other = client.post("/api/auth/login", json={"email": "u9@x.test", "password": "bad"}, headers={"X-Forwarded-For": "203.0.113.8"})
    assert other.status_code == 401  # different client, not throttled


def test_csrf_accepts_https_origin_behind_trusted_proxy(client, monkeypatch):
    """behind a tls-terminating proxy an https origin is accepted though the request scheme is http"""
    monkeypatch.setenv("NORINTH_TRUST_PROXY", "1")
    headers = {"Origin": "https://norinth.example.com", "Host": "internal:8001",
               "X-Forwarded-Proto": "https", "X-Forwarded-Host": "norinth.example.com"}
    # mutating cookie-route call reaches auth instead of being csrf-rejected
    resp = client.post("/api/auth/login", json={"email": "x@y.z", "password": "nope"}, headers=headers)
    assert resp.status_code != 403  # reaches auth (401 invalid creds), not CSRF-rejected

    # genuinely cross-site origin still rejected
    bad = client.post("/api/auth/login", json={"email": "x@y.z", "password": "nope"},
                      headers={"Origin": "https://evil.example", "Host": "internal:8001",
                               "X-Forwarded-Proto": "https", "X-Forwarded-Host": "norinth.example.com"})
    assert bad.status_code == 403


def test_session_cookie_is_secure_over_https_even_without_the_admin_password_var(client, monkeypatch):
    """Secure is decided by how the request arrived, not by an unrelated env var

    the test env runs in development-defaults mode (NORINTH_SUPER_ADMIN_PASSWORD
    unset), which is exactly the tls deployment that seeds its admin some other
    way. an https request (here via a trusted proxy's x-forwarded-proto) must
    still yield a Secure cookie; the old logic tied Secure to the admin-password
    var and would ship it without Secure
    """
    monkeypatch.delenv("NORINTH_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("NORINTH_TRUST_PROXY", "1")
    resp = client.post("/api/auth/login", json=GOOD, headers={
        "Origin": "https://testserver",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "testserver",
    })
    assert resp.status_code == 200, resp.text
    assert "secure" in resp.headers.get("set-cookie", "").lower(), resp.headers.get("set-cookie")


def test_session_cookie_is_not_secure_over_plain_http_dev(client, monkeypatch):
    """plain-http dev must not get a Secure cookie or the browser drops it"""
    monkeypatch.delenv("NORINTH_COOKIE_SECURE", raising=False)
    resp = client.post("/api/auth/login", json=GOOD, headers={"Origin": "http://testserver"})
    assert resp.status_code == 200, resp.text
    assert "secure" not in resp.headers.get("set-cookie", "").lower(), resp.headers.get("set-cookie")


def test_session_cookie_has_httponly_samesite_and_secure(client, monkeypatch):
    """the session cookie flags decide whether a session is stealable: HttpOnly
    keeps it out of reach of XSS, SameSite blunts CSRF, Secure keeps it off
    plaintext. a flag silently flipped off would ship without this"""
    # force Secure on regardless of the test's development mode
    monkeypatch.setenv("NORINTH_COOKIE_SECURE", "1")
    resp = client.post("/api/auth/login", json=GOOD)
    assert resp.status_code == 200, resp.text

    set_cookie = resp.headers.get("set-cookie", "")
    assert "norinth_session=" in set_cookie
    lowered = set_cookie.lower()
    assert "httponly" in lowered, set_cookie
    assert "samesite=lax" in lowered, set_cookie
    assert "secure" in lowered, set_cookie
    assert "path=/" in lowered, set_cookie

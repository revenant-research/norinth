"""Login throttle counts atomically and keys off a trustworthy IP (M99).

The lockout counter was a non-atomic read-modify-write, so concurrent failures
were undercounted and an attacker could outrun the lockout; the IP throttle key
took the attacker-controlled leftmost X-Forwarded-For hop.
"""

from __future__ import annotations

import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_concurrent_failures_are_all_counted(client):
    from app.storage import login_attempts as la

    subject = la.email_subject("victim@acme.test")

    # Fire many failures concurrently; none may be lost to a lost update.
    threads = [threading.Thread(target=la.register_failure, args=(subject,)) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    from app.storage.raw_events import connect

    with connect() as connection:
        row = connection.execute(
            "SELECT failed_count FROM login_throttle WHERE subject = ?", (subject,)
        ).fetchone()
    # Exactly one increment per failure (no lost updates); and well over the
    # threshold, so the subject is locked.
    assert row["failed_count"] == 40
    assert la.is_locked(subject)


def test_reaching_threshold_locks_the_subject(client):
    from app.storage import login_attempts as la

    subject = la.email_subject("user@acme.test")
    for _ in range(la.LOCKOUT_THRESHOLD - 1):
        la.register_failure(subject)
    assert not la.is_locked(subject)  # not yet at the threshold
    la.register_failure(subject)
    assert la.is_locked(subject)  # locked on reaching the threshold


def test_client_ip_uses_rightmost_trusted_hop(monkeypatch):
    monkeypatch.setenv("NORINTH_TRUST_PROXY", "1")
    from app.api.auth import client_ip

    class _Req:
        def __init__(self, xff):
            self.headers = {"x-forwarded-for": xff}
            self.client = type("C", (), {"host": "10.0.0.9"})()

    # Client prepends a forged address; the real client is the rightmost hop the
    # single trusted proxy appended.
    monkeypatch.setenv("NORINTH_TRUSTED_PROXY_HOPS", "1")
    assert client_ip(_Req("1.2.3.4, 203.0.113.7")) == "203.0.113.7"

    # Two trusted proxies: the client address is two from the right.
    monkeypatch.setenv("NORINTH_TRUSTED_PROXY_HOPS", "2")
    assert client_ip(_Req("1.2.3.4, 203.0.113.7, 10.0.0.1")) == "203.0.113.7"


def test_client_ip_ignores_forwarded_header_without_trusted_proxy(monkeypatch):
    monkeypatch.delenv("NORINTH_TRUST_PROXY", raising=False)
    from app.api.auth import client_ip

    class _Req:
        headers = {"x-forwarded-for": "1.2.3.4"}
        client = type("C", (), {"host": "10.0.0.9"})()

    assert client_ip(_Req()) == "10.0.0.9"

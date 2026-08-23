"""SMTP STARTTLS verifies the server certificate by default (audit finding M109)."""

from __future__ import annotations

import pathlib
import ssl
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


class _FakeSMTP:
    last_context: ssl.SSLContext | None = None

    def __init__(self, host, port, timeout=20):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        _FakeSMTP.last_context = context

    def login(self, user, password):
        pass

    def send_message(self, msg):
        pass


def _send(monkeypatch):
    import app.services.notifications as notifications

    monkeypatch.setenv("NORINTH_SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(notifications.smtplib, "SMTP", _FakeSMTP)
    notifications._send_email("to@example.test", "hi", {"text": "body"})
    return _FakeSMTP.last_context


def test_starttls_verifies_by_default(monkeypatch):
    monkeypatch.delenv("NORINTH_SMTP_INSECURE", raising=False)
    context = _send(monkeypatch)
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_starttls_can_opt_out_for_internal_relay(monkeypatch):
    monkeypatch.setenv("NORINTH_SMTP_INSECURE", "1")
    context = _send(monkeypatch)
    assert context is not None
    assert context.verify_mode == ssl.CERT_NONE

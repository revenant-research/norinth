"""Host header is validated so it cannot redirect identity flows (audit M98)."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_allowed_hosts_from_public_base_url(monkeypatch):
    from app.main import _allowed_hosts

    monkeypatch.delenv("NORINTH_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("NORINTH_PUBLIC_BASE_URL", "https://norinth.acme.com")
    assert _allowed_hosts() == ["norinth.acme.com"]


def test_allowed_hosts_explicit_list(monkeypatch):
    from app.main import _allowed_hosts

    monkeypatch.setenv("NORINTH_ALLOWED_HOSTS", "a.example, b.example")
    monkeypatch.setenv("NORINTH_PUBLIC_BASE_URL", "https://c.example")
    assert _allowed_hosts() == ["a.example", "b.example", "c.example"]


def test_allowed_hosts_defaults_to_wildcard_for_dev(monkeypatch):
    from app.main import _allowed_hosts

    monkeypatch.delenv("NORINTH_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("NORINTH_PUBLIC_BASE_URL", raising=False)
    assert _allowed_hosts() == ["*"]


def test_trusted_host_middleware_rejects_spoofed_host():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    probe = FastAPI()
    probe.add_middleware(TrustedHostMiddleware, allowed_hosts=["norinth.acme.com"])

    @probe.get("/api/auth/saml/x/start")
    def _start():
        return {"ok": True}

    tc = TestClient(probe)
    assert tc.get("/api/auth/saml/x/start", headers={"host": "norinth.acme.com"}).status_code == 200
    assert tc.get("/api/auth/saml/x/start", headers={"host": "evil.example"}).status_code == 400

"""host header validated only where identity urls are built, not globally"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


class _Req:
    def __init__(self, host: str, base="http://testserver/"):
        self.headers = {"host": host}
        self.base_url = base


def test_public_base_url_takes_precedence(monkeypatch):
    from app.services.base_url import external_base_url

    monkeypatch.setenv("NORINTH_PUBLIC_BASE_URL", "https://norinth.acme.com")
    # hostile host is ignored when a public base url is configured
    assert external_base_url(_Req("evil.example")) == "https://norinth.acme.com"


def test_host_must_be_in_allowlist_when_no_public_base_url(monkeypatch):
    from app.services.base_url import external_base_url
    from fastapi import HTTPException

    monkeypatch.delenv("NORINTH_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setenv("NORINTH_ALLOWED_HOSTS", "norinth.acme.com")

    assert external_base_url(_Req("norinth.acme.com")) == "http://testserver"
    assert external_base_url(_Req("norinth.acme.com:443")) == "http://testserver"
    with pytest.raises(HTTPException):
        external_base_url(_Req("evil.example"))


def test_unconfigured_allows_any_host_for_dev(monkeypatch):
    from app.services.base_url import external_base_url

    monkeypatch.delenv("NORINTH_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("NORINTH_ALLOWED_HOSTS", raising=False)
    # no allowlist means dev mode so any host is accepted
    assert external_base_url(_Req("anything.local")) == "http://testserver"


def test_allowed_hosts_helper(monkeypatch):
    from app.services.base_url import allowed_hosts

    monkeypatch.setenv("NORINTH_ALLOWED_HOSTS", "a.example, b.example")
    monkeypatch.setenv("NORINTH_PUBLIC_BASE_URL", "https://c.example")
    assert allowed_hosts() == ["a.example", "b.example", "c.example"]

    monkeypatch.delenv("NORINTH_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("NORINTH_PUBLIC_BASE_URL", raising=False)
    assert allowed_hosts() is None


def test_health_is_never_host_restricted(client):
    # /health must not be host-restricted or the container never goes healthy
    resp = client.get("/health", headers={"host": "some-other-host.example"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

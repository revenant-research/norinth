"""egress guard blocks ssrf to loopback, private and cloud-metadata addresses"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


@pytest.fixture(autouse=True)
def _enforce(monkeypatch):
    monkeypatch.setenv("NORINTH_ALLOW_PRIVATE_EGRESS", "0")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:1/x",
    "http://localhost:8001/x",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:22/x",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/",
    "http://metadata.google.internal/",  # resolves to link-local in gcp; here to a private/absent addr
    "ftp://example.com/x",
])
def test_blocked_urls(url):
    from app.services.net_guard import EgressError, validate_external_url

    with pytest.raises(EgressError):
        validate_external_url(url)


def test_public_url_is_allowed(monkeypatch):
    from app.services.net_guard import validate_external_url

    # a public ip literal is allowed (no dns needed)
    validate_external_url("https://93.184.216.34/ok")  # public ip literal

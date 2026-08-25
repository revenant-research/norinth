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


def test_safe_urlopen_refuses_to_follow_a_redirect_to_a_blocked_host(monkeypatch):
    """a target that passes the initial check but 302s to metadata is refused

    validate_external_url only vets the first host; urllib follows redirects, so
    without per-hop re-validation an allowed host could bounce the fetch to the
    cloud metadata endpoint. safe_urlopen must re-run the guard on every hop
    """
    import http.server
    import ipaddress
    import threading

    from app.services import net_guard

    # keep the guard on, but treat loopback as public so the local decoy server
    # is reachable; only the metadata endpoint stays blocked. this isolates the
    # redirect-following behaviour from the initial-host check
    monkeypatch.setattr(
        net_guard,
        "_is_blocked",
        lambda ip: ipaddress.ip_address(ip) == ipaddress.ip_address("169.254.169.254"),
    )

    class _Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

        def log_message(self, *args):  # silence the test server
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(net_guard.EgressError):
            net_guard.safe_urlopen(f"http://127.0.0.1:{port}/", timeout=5)
    finally:
        server.shutdown()
        thread.join()

"""egress guard against server-side request forgery

webhook urls and oidc endpoints are configured by org admins and then fetched by
the server, so a malicious or compromised org admin could point them at internal
services or the cloud metadata endpoint (169.254.169.254). before any such fetch
we resolve the host and refuse loopback, private, link-local, reserved and
multicast addresses

set NORINTH_ALLOW_PRIVATE_EGRESS=1 to disable the check (local dev where a
webhook receiver runs on 127.0.0.1)
"""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.request
from typing import Any
from urllib.parse import urlparse


class EgressError(Exception):
    pass


def _allow_private() -> bool:
    return os.getenv("NORINTH_ALLOW_PRIVATE_EGRESS", "0").lower() in {"1", "true", "yes"}


def _is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or addr == ipaddress.ip_address("169.254.169.254")  # cloud metadata (also link-local, kept explicit)
    )


def validate_external_url(url: str) -> None:
    """raise unless url is http(s) and its host resolves only to public addrs; call right before fetching"""
    if _allow_private():
        return
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise EgressError(f"only http(s) URLs are allowed, got {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise EgressError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise EgressError(f"could not resolve host {host!r}") from error
    for info in infos:
        # sockaddr[0] is the address string for both IPv4 and IPv6; be explicit
        # so the block check is never handed a non-string
        ip = str(info[4][0])
        if _is_blocked(ip):
            raise EgressError(f"host {host!r} resolves to a non-public address ({ip}); refusing to connect")


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """re-run the egress guard on every redirect target

    validate_external_url only vets the initial host. urllib follows redirects
    by default, so without this a target that passes the check can 302 to the
    cloud metadata endpoint or an internal service and the guard is bypassed
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        validate_external_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(url_or_request: Any, *, timeout: float = 10.0):
    """urlopen that validates the initial target and every redirect hop

    use this instead of urllib.request.urlopen for any fetch of an
    operator-configured URL (webhooks, OIDC endpoints)
    """
    target = url_or_request.full_url if isinstance(url_or_request, urllib.request.Request) else url_or_request
    validate_external_url(target)
    opener = urllib.request.build_opener(_ValidatingRedirectHandler())
    return opener.open(url_or_request, timeout=timeout)

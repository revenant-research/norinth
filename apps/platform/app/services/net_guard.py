"""Egress guard against server-side request forgery.

Webhook URLs and OIDC endpoints are configured by organization administrators
and then fetched by the server, so an attacker who is (or compromises) an org
admin could point them at internal services or the cloud metadata endpoint
(169.254.169.254). Before any such fetch we resolve the host and refuse
loopback, private, link-local, reserved and multicast addresses.

Set NORINTH_ALLOW_PRIVATE_EGRESS=1 to disable the check (local development,
where a webhook receiver runs on 127.0.0.1).
"""

from __future__ import annotations

import ipaddress
import os
import socket
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
        or addr == ipaddress.ip_address("169.254.169.254")  # cloud metadata (also link-local, explicit for clarity)
    )


def validate_external_url(url: str) -> None:
    """Raise EgressError unless url is an http(s) URL whose host resolves only
    to public addresses. Call immediately before fetching."""
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
        ip = info[4][0]
        if _is_blocked(ip):
            raise EgressError(f"host {host!r} resolves to a non-public address ({ip}); refusing to connect")

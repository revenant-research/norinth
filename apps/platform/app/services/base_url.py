"""Trusted external base URL for identity flows.

The SAML Audience/Recipient and the OIDC redirect_uri must not be derived from an
attacker-controlled Host header (audit finding M98). This is validated ONLY where
those URLs are built — never globally — so health/liveness probes and ordinary
requests, which legitimately arrive with a localhost or pod-IP Host, are never
rejected. Set NORINTH_PUBLIC_BASE_URL in production and the Host is ignored
entirely; otherwise the Host is accepted only when it is in NORINTH_ALLOWED_HOSTS
(and, with neither configured, anything is accepted for local development).
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from fastapi import HTTPException, Request


def allowed_hosts() -> list[str] | None:
    """Configured host allowlist, or None when unrestricted (local dev)."""
    hosts: list[str] = []
    raw = os.getenv("NORINTH_ALLOWED_HOSTS")
    if raw:
        hosts.extend(h.strip() for h in raw.split(",") if h.strip())
    public = os.getenv("NORINTH_PUBLIC_BASE_URL")
    if public:
        host = urlsplit(public).hostname
        if host and host not in hosts:
            hosts.append(host)
    return hosts or None


def external_base_url(request: Request) -> str:
    """Return the trusted external base URL (scheme://host, no trailing slash).

    Prefers NORINTH_PUBLIC_BASE_URL. Otherwise falls back to the request base URL,
    but only after checking the Host against the allowlist so an identity flow
    cannot be pointed at an attacker's domain.
    """
    public = os.getenv("NORINTH_PUBLIC_BASE_URL")
    if public:
        return public.rstrip("/")
    allowed = allowed_hosts()
    if allowed is not None:
        host = (request.headers.get("host") or "").split(",")[0].strip()
        # Match host with or without an explicit port.
        hostname = host.rsplit(":", 1)[0] if ":" in host else host
        if host not in allowed and hostname not in allowed:
            raise HTTPException(status_code=400, detail="Request Host is not in NORINTH_ALLOWED_HOSTS")
    return str(request.base_url).rstrip("/")

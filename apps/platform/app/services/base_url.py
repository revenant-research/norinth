# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""trusted external base url for identity flows

the saml audience/recipient and the oidc redirect_uri must not come from an
attacker-controlled host header. checked only where those urls are built, not
globally, so health probes and ordinary requests arriving with a localhost or
pod-ip host are never rejected. set NORINTH_PUBLIC_BASE_URL in production and the
host is ignored; otherwise the host must be in NORINTH_ALLOWED_HOSTS (with
neither configured, anything is accepted for local dev)
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from fastapi import HTTPException, Request


def allowed_hosts() -> list[str] | None:
    """configured host allowlist, or None when unrestricted (local dev)"""
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
    """trusted external base url (scheme://host, no trailing slash)

    prefers NORINTH_PUBLIC_BASE_URL, else the request base url but only after
    checking the host against the allowlist so an identity flow can't be pointed
    at an attacker's domain
    """
    public = os.getenv("NORINTH_PUBLIC_BASE_URL")
    if public:
        return public.rstrip("/")
    allowed = allowed_hosts()
    if allowed is not None:
        host = (request.headers.get("host") or "").split(",")[0].strip()
        # match with or without an explicit port
        hostname = host.rsplit(":", 1)[0] if ":" in host else host
        if host not in allowed and hostname not in allowed:
            raise HTTPException(status_code=400, detail="Request Host is not in NORINTH_ALLOWED_HOSTS")
    return str(request.base_url).rstrip("/")

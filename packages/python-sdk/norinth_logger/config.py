# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from os import getenv
from typing import Any


def _split_env(value: str | None) -> tuple[str, ...]:
    """comma-separated env list -> tuple; empty when unset"""
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class NorinthConfig:
    api_key: str
    signing_secret: str | None = None
    endpoint: str = "http://localhost:8001"
    project: str = "default"
    environment: str = "development"
    service: str = "unknown-service"
    # optional governance identity for the host app; set once at init so an existing
    # app shows in inventory without threading governance fields through its own code
    application_name: str | None = None
    use_case: str | None = None
    mode: str = "observe"
    capture_content: bool = False
    # extra metadata keys this app wants recorded in the clear on top of the
    # governance labels in privacy.METADATA_SAFE_KEYS; everything else is
    # hashed while capture_content is off
    metadata_allowlist: tuple[str, ...] = ()
    # incident descriptions are written by a person for the governance record,
    # but they are still free text that can carry phi, so capturing them is an
    # explicit opt-in like any other content
    capture_incident_details: bool = False
    async_transport: bool = True
    fail_open: bool = True
    max_queue_size: int = 1000
    flush_interval_seconds: float = 2.0
    timeout_seconds: float = 2.0
    # delivery durability: transient failures (timeout, conn error, 5xx, 408, 429)
    # retried with backoff; if still failing and a spool dir is set, the batch is
    # written to disk and retried next flush instead of dropped
    max_send_retries: int = 3
    retry_backoff_seconds: float = 0.5
    # None picks a private per-service directory (see spool.py); "off" disables
    # spooling; anything else is used as given. with capture_content on there is
    # no default, so raw content never lands on disk unasked
    spool_dir: str | None = None
    spool_max_bytes: int = 32 * 1024 * 1024
    # evidence-grade delivery. the defaults above are tuned for observability in a
    # request path: async, fail-open, bounded queue, never block the host app. a
    # batch that fails every retry is spooled when there is somewhere to put it
    # and dropped otherwise, and a drop is silent -- you find out at audit.
    # durable=True refuses to construct a client without a spool, so such a
    # deployment fails at startup instead. it does not make delivery
    # synchronous; it makes the durability decision explicit and checked
    durable: bool = False

    @property
    def fingerprint_key(self) -> str:
        """key for content fingerprints (privacy.stable_hash)

        an unkeyed digest of low-entropy content (an MRN, a short prompt) is a
        lookup table, not a privacy control — anyone can brute-force the
        preimage. an explicit signing_secret wins so fingerprints can stay
        stable across services and api-key rotation; otherwise the key is
        derived from the api key, which every install already holds as a
        secret, so a default install never emits unkeyed digests. rotating the
        api key rotates the derived key (old and new fingerprints stop
        linking); pin signing_secret if that continuity matters to you
        """
        if self.signing_secret:
            return self.signing_secret
        return hmac.new(
            self.api_key.encode("utf-8"), b"norinth-fingerprint-key-v1", hashlib.sha256
        ).hexdigest()

    @classmethod
    def from_env(cls, **overrides: object) -> NorinthConfig:
        values: dict[str, Any] = {
            "api_key": getenv("NORINTH_API_KEY", "dev"),
            "signing_secret": getenv("NORINTH_SIGNING_SECRET"),
            "endpoint": getenv("NORINTH_ENDPOINT", "http://localhost:8001"),
            "project": getenv("NORINTH_PROJECT", "default"),
            "environment": getenv("NORINTH_ENVIRONMENT", "development"),
            "service": getenv("NORINTH_SERVICE", "unknown-service"),
            "application_name": getenv("NORINTH_APPLICATION_NAME"),
            "use_case": getenv("NORINTH_USE_CASE"),
            "mode": getenv("NORINTH_MODE", "observe"),
            "capture_content": getenv("NORINTH_CAPTURE_CONTENT", "false").lower() == "true",
            "capture_incident_details": getenv("NORINTH_CAPTURE_INCIDENT_DETAILS", "false").lower() == "true",
            "metadata_allowlist": _split_env(getenv("NORINTH_METADATA_ALLOWLIST")),
            "spool_dir": getenv("NORINTH_SPOOL_DIR"),
            "durable": getenv("NORINTH_DURABLE", "false").lower() == "true",
        }
        values.update({key: value for key, value in overrides.items() if value is not None})
        return cls(**values)

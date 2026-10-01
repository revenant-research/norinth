# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Opt-in synchronous authorization client, separate from fail-open telemetry.

No effect is executed by this client. An executor must consume an exact permit
immediately before its effect, abort on every error, and report the outcome.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

Transport = Callable[[str, dict[str, Any] | None], dict[str, Any]]


class PortableError(RuntimeError):
    """No permission can be inferred from an unavailable or invalid response."""


class PermissionDenied(PortableError):
    def __init__(self, outcome: str, reasons: list[str]):
        self.outcome = outcome
        self.reasons = reasons
        super().__init__("Norinth did not authorize this effect: " + outcome)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward an integration credential to a redirect destination.
        return None


class PortableClient:
    def __init__(
        self,
        endpoint: str,
        integration_token: str,
        *,
        timeout: float = 5,
        allow_insecure: bool = False,
        transport: Transport | None = None,
    ):
        parsed = urllib.parse.urlsplit(endpoint)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Provide a Norinth endpoint without credentials, query, or fragment")
        if parsed.scheme not in {"https", "http"} or (parsed.scheme != "https" and not allow_insecure):
            raise ValueError("HTTPS is required unless allow_insecure is explicitly enabled")
        if (
            not 0 < timeout <= 60
            or not integration_token.startswith("nri_")
            or any(c.isspace() for c in integration_token)
        ):
            raise ValueError("Provide a scoped integration credential and a timeout within 60 seconds")
        self.endpoint = endpoint.rstrip("/")
        self._token = integration_token
        self.timeout = timeout
        self._transport = transport or self._http

    def _http(self, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        request = urllib.request.Request(
            self.endpoint + path,
            data=json.dumps(payload, allow_nan=False).encode() if payload is not None else None,
            headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise PortableError("Norinth returned an unexpected status")
                raw = response.read(2097153)
                if len(raw) > 2097152:
                    raise PortableError("Norinth response exceeded the limit")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise PortableError("Norinth returned an invalid contract")
                return result
        except (urllib.error.URLError, OSError, ValueError) as error:
            # Do not echo response bodies or a URL containing sensitive data.
            raise PortableError("Norinth request failed; do not execute the effect") from error

    def _call(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return self._transport("/v1/portable" + path, payload)
        except PortableError:
            raise
        except Exception as error:
            raise PortableError("Norinth request failed; do not execute the effect") from error

    def register_system(self, system: dict[str, Any]) -> dict[str, Any]:
        return self._call("/systems", system)["system"]

    def workspace(self, system_id: str, *, offset: int = 0) -> dict[str, Any]:
        return self._call(
            "/systems/"
            + urllib.parse.quote(system_id, safe="")
            + "/workspace?"
            + urllib.parse.urlencode({"offset": offset})
        )

    def controls(self, system_id: str, revision_id: str) -> dict[str, Any]:
        return self._call(
            "/systems/"
            + urllib.parse.quote(system_id, safe="")
            + "/controls?"
            + urllib.parse.urlencode({"revision_id": revision_id})
        )

    def submit_revision(self, system_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return self._call("/systems/" + urllib.parse.quote(system_id, safe="") + "/revisions", manifest)["revision"]

    def observe(self, system_id: str, observation: dict[str, Any]) -> dict[str, Any]:
        return self._call("/systems/" + urllib.parse.quote(system_id, safe="") + "/observations", observation)[
            "observation"
        ]

    def authorize(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._call("/authorizations", request)

    def consume(self, authorization: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
        try:
            record = authorization["authorization"]
            outcome = record["body"]["outcome"]
            if outcome != "allow":
                raise PermissionDenied(outcome, record["body"]["reasons"])
            token = authorization["token"]
            if not isinstance(token, str) or not token.startswith("nrp_"):
                raise PortableError("Norinth did not provide a permit")
            consumed = self._call("/authorizations/consume", {"token": token, "request": request})["authorization"]
            if (
                consumed["record_id"] != record["record_id"]
                or consumed["state"] != "consumed"
                or consumed["body"]["outcome"] != "allow"
                or consumed["body"].get("request_digest") != record["body"].get("request_digest")
            ):
                raise PortableError("Norinth did not consume this exact authorization")
            if consumed["body"].get("policy_id") != record["body"].get("policy_id"):
                raise PortableError("Norinth did not consume this exact authorization")
            return consumed
        except (KeyError, TypeError) as error:
            raise PortableError("Norinth returned an incomplete authorization") from error

    def receipt(self, authorization_id: str, *, outcome: str, evidence_ref: str) -> dict[str, Any]:
        return self._call(
            "/receipts", {"authorization_id": authorization_id, "outcome": outcome, "evidence_ref": evidence_ref}
        )["receipt"]

    def verify(self, receipt_id: str, observation_id: str) -> dict[str, Any]:
        return self._call(
            "/receipts/" + urllib.parse.quote(receipt_id, safe="") + "/verify", {"observation_id": observation_id}
        )["receipt"]

    def redeem(self, delegation_token: str) -> dict[str, Any]:
        return self._call("/delegations/redeem", {"token": delegation_token})["record"]

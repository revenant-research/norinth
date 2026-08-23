"""Eval-evidence attestation: canonical statement + Ed25519 verification.

The statement format is the contract between the signer (CI, via the SDK's
``norinth_logger.attest``) and the platform. It is deliberately duplicated on
both sides rather than imported across the SDK/platform boundary, exactly like
the wire schema; ``tests/test_evidence_attestation.py`` pins both to the same
bytes.

Statement v1 = canonical JSON (sorted keys, no whitespace, ASCII) of the fields
that make a passing eval meaningful as gate evidence. Tenant, application,
workflow, trace and span are included so a signature cannot be replayed onto a
different organization, application, or run.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STATEMENT_TYPE = "norinth.eval.attestation/v1"
MAX_PEM_LENGTH = 4096


class AttestationError(Exception):
    pass


def build_eval_statement(event: dict[str, Any]) -> bytes:
    attrs = event.get("attributes") or {}
    meta = attrs.get("metadata") or {}
    statement = {
        "type": STATEMENT_TYPE,
        "tenant_id": meta.get("tenant_id"),
        "application_name": meta.get("application_name"),
        "workflow_name": meta.get("workflow_name"),
        "eval_id": attrs.get("eval_id") or attrs.get("eval_name") or event.get("name"),
        "passed": bool(attrs.get("passed")),
        "score": attrs.get("score"),
        "prompt_version": attrs.get("prompt_version"),
        "artifact_ref": attrs.get("artifact_ref"),
        "trace_id": event.get("trace_id"),
        "span_id": event.get("span_id"),
        "timestamp": event.get("timestamp"),
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def load_public_key(pem: str) -> Ed25519PublicKey:
    if len(pem) > MAX_PEM_LENGTH:
        raise AttestationError("public key is too long")
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError) as error:
        raise AttestationError("public key is not valid PEM") from error
    if not isinstance(key, Ed25519PublicKey):
        raise AttestationError("only Ed25519 attestation keys are supported")
    return key


def public_key_fingerprint(pem: str) -> str:
    try:
        raw = load_public_key(pem).public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    except AttestationError:
        return "invalid"
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:32]


def verify_eval_attestation(event: dict[str, Any], public_key_pem: str, signature_b64: str) -> None:
    """Raise AttestationError unless ``signature_b64`` is a valid Ed25519
    signature over the canonical statement for ``event`` under the key."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as error:
        raise AttestationError("attestation signature is not valid base64") from error
    key = load_public_key(public_key_pem)
    try:
        key.verify(signature, build_eval_statement(event))
    except InvalidSignature as error:
        raise AttestationError("attestation signature does not match the eval result") from error

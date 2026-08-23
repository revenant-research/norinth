"""sign eval results so gates accept them as attested evidence

Usage in CI, after your eval job produces a result::

    from norinth_logger.attest import sign_eval_result

    event = {
        "type": "eval.result", "trace_id": ..., "span_id": ..., "timestamp": ...,
        "attributes": {"eval_id": "safety-suite", "passed": True, "score": 0.97,
                       "prompt_version": "v12", "artifact_ref": "sha256:...",
                       "metadata": {"tenant_id": "acme", "application_name": "Claims",
                                    "workflow_name": "triage"}},
    }
    sign_eval_result(event, private_key_pem=os.environ["NORINTH_ATTEST_KEY"], key_id="nak_...")
    # event["attributes"]["attestation"] is now {"key_id": ..., "signature": ...}

Generate a key pair once (keep the private half in your CI secret store and
register the public half under Identity & Integrations -> Evidence attestation)::

    python -m norinth_logger.attest keygen

Requires the optional ``cryptography`` package (``pip install norinth-logger[attest]``).

The signed statement must stay byte-identical to what the platform verifies.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any

STATEMENT_TYPE = "norinth.eval.attestation/v1"


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


def _require_crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as error:  # pragma: no cover
        raise RuntimeError(
            "evidence attestation needs the 'cryptography' package: pip install 'norinth-logger[attest]'"
        ) from error
    return serialization, ed25519


def sign_eval_result(event: dict[str, Any], *, private_key_pem: str | bytes, key_id: str) -> dict[str, Any]:
    """sign an eval.result event in place; metadata tenant/app/workflow must match the ingestion key or verify fails"""
    if event.get("type") != "eval.result":
        raise ValueError("only eval.result events can be attested")
    serialization, ed25519 = _require_crypto()
    pem = private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("attestation requires an Ed25519 private key")
    signature = key.sign(build_eval_statement(event))
    attrs = event.setdefault("attributes", {})
    attrs["attestation"] = {"key_id": key_id, "signature": base64.b64encode(signature).decode("ascii")}
    return event


def generate_keypair() -> tuple[str, str]:
    """fresh ed25519 keypair as (private_pem, public_pem)"""
    serialization, ed25519 = _require_crypto()
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    return private_pem, public_pem


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["keygen"]:
        private_pem, public_pem = generate_keypair()
        sys.stdout.write(
            "# Private key: store in your CI secret store (e.g. NORINTH_ATTEST_KEY). Never commit it.\n"
            + private_pem
            + "\n# Public key: register under Identity & Integrations -> Evidence attestation.\n"
            + public_pem
        )
        return 0
    sys.stderr.write("usage: python -m norinth_logger.attest keygen\n")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

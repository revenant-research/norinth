from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

GOVERNANCE_CONTEXT_FIELDS = {
    "tenant_id",
    "user_id",
    "application_name",
    "use_case",
    "model_purpose",
}

# Governance context values are identifiers/labels, not free-form content; cap
# their length so a stray large field can't ride out under a governance label.
_MAX_CONTEXT_LEN = 256


def _canonical_bytes(value: Any) -> bytes:
    """Deterministic byte encoding for hashing.

    repr() is not canonical — dict ordering and object memory addresses make it
    unstable and unsuitable as a content fingerprint. Strings/bytes
    hash directly; structured values use sorted-key JSON; everything else falls
    back to repr.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8", "replace")
    except Exception:
        return repr(value).encode("utf-8", "replace")


def stable_hash(value: Any, hash_key: str | None = None) -> str:
    """Content fingerprint. When a hash_key is supplied it is an HMAC, so the
    digest is not a globally-reversible dictionary lookup and cannot be linked
    across tenants. Configure NORINTH_SIGNING_SECRET to key it."""
    data = _canonical_bytes(value)
    if hash_key:
        digest = hmac.new(hash_key.encode("utf-8"), data, hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def summarize_value(value: Any, capture_content: bool, hash_key: str | None = None) -> dict[str, Any]:
    if value is None:
        return {"type": "None", "is_none": True}

    summary: dict[str, Any] = {
        "type": type(value).__name__,
        "hash": stable_hash(value, hash_key),
    }
    if isinstance(value, (str, bytes, list, tuple, dict, set)):
        summary["size"] = len(value)
    if capture_content:
        summary["content"] = value if isinstance(value, (str, int, float, bool, list, dict)) else repr(value)
    return summary


def summarize_error(exc: BaseException, capture_content: bool, hash_key: str | None = None) -> dict[str, Any]:
    """Summarize an exception for telemetry.

    The message is content-derived: provider 4xx errors echo request inputs, and
    application exceptions routinely interpolate PII/PHI (e.g. an invalid SSN or
    patient identifier). It is therefore hashed and length-reported by default,
    and only included verbatim when capture_content is explicitly enabled
. The exception *type* is always safe to record.
    """
    message = str(exc)
    result: dict[str, Any] = {
        "type": type(exc).__name__,
        "message_hash": stable_hash(message, hash_key),
        "message_size": len(message),
    }
    if capture_content:
        result["message"] = message
    return result


def summarize_call(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    capture_content: bool,
    hash_key: str | None = None,
) -> dict[str, Any]:
    return {
        "args": [summarize_value(arg, capture_content, hash_key) for arg in args],
        "kwargs": {key: summarize_value(value, capture_content, hash_key) for key, value in kwargs.items()},
    }


def object_to_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "__dict__"):
        return vars(value)
    return {}


def infer_governance_context(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, str]:
    context: dict[str, str] = {}
    for value in (*args, *kwargs.values()):
        fields = object_to_mapping(value)
        for key in GOVERNANCE_CONTEXT_FIELDS:
            if key in context:
                continue
            field_value = fields.get(key)
            if field_value is None:
                continue
            # Governance context fields are scalar identifiers/labels. Skip nested
            # structures so request-body content is never stringified wholesale,
            # and cap length.
            if isinstance(field_value, (dict, list, tuple, set)):
                continue
            text = str(field_value)
            if len(text) > _MAX_CONTEXT_LEN:
                text = text[:_MAX_CONTEXT_LEN]
            context[key] = text
    return context

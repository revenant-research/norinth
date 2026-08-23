from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

# Patterns masked from captured content before it leaves the process. This is
# the redaction the README refers to: even with content capture enabled, common
# secrets and direct identifiers are replaced (audit finding H15). It is
# deliberately conservative — high-signal patterns only — so it does not mangle
# ordinary prose.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[redacted-email]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[redacted-ssn]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[redacted-card]"),
    (re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9]{16,}\b"), "[redacted-key]"),
    (re.compile(r"\b[A-Za-z0-9_-]{40,}\b"), "[redacted-token]"),
)

# Sentinel: this value has no representable content and must be omitted entirely
# (never repr'd, which would leak object state such as API keys held on a config
# dataclass or client instance passed to a traced function).
_OMIT_CONTENT = object()


def redact_text(value: str) -> str:
    for pattern, replacement in _REDACTIONS:
        value = pattern.sub(replacement, value)
    return value


def _capture_content(value: Any) -> Any:
    """Return redacted, JSON-native content, or ``_OMIT_CONTENT``.

    Only JSON-native scalars and containers are ever captured; any other object
    (a provider client, a config dataclass, an arbitrary instance) is omitted
    rather than repr'd, closing the API-key-via-repr leak in audit finding H15.
    """
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (list, tuple)):
        return [_capture_content(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _capture_content(item) for key, item in value.items()}
    return _OMIT_CONTENT

GOVERNANCE_CONTEXT_FIELDS = {
    "user_id",
    "application_name",
    "use_case",
    "model_purpose",
}

# The Norinth platform tenant is authoritative from the ingestion key and is
# stamped server-side; the SDK must never infer it from an application's request
# body. Doing so stamped ``metadata.tenant_id`` with the application's *own*
# customer identifier, which the platform then rejected (403) because it did not
# match the ingestion key's tenant — discarding the entire batch (audit finding
# H12). An app's customer/tenant identifier is still useful governance context,
# so any of these fields is recorded under a non-colliding key the platform does
# not use for routing or authorization.
_APP_TENANT_FIELDS = ("tenant_id", "org_id", "organization_id", "account_id", "customer_id")
_APP_TENANT_OUTPUT_KEY = "subject_tenant"

# Governance context values are identifiers/labels, not free-form content; cap
# their length so a stray large field can't ride out under a governance label.
_MAX_CONTEXT_LEN = 256


def _canonical_bytes(value: Any) -> bytes:
    """Deterministic byte encoding for hashing.

    repr() is not canonical — dict ordering and object memory addresses make it
    unstable and unsuitable as a content fingerprint (audit H-12). Strings/bytes
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
    across tenants (audit H-12). Configure NORINTH_SIGNING_SECRET to key it."""
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
        content = _capture_content(value)
        if content is not _OMIT_CONTENT:
            summary["content"] = content
    return summary


def summarize_error(exc: BaseException, capture_content: bool, hash_key: str | None = None) -> dict[str, Any]:
    """Summarize an exception for telemetry.

    The message is content-derived: provider 4xx errors echo request inputs, and
    application exceptions routinely interpolate PII/PHI (e.g. an invalid SSN or
    patient identifier). It is therefore hashed and length-reported by default,
    and only included verbatim when capture_content is explicitly enabled
    (audit H-13). The exception *type* is always safe to record.
    """
    message = str(exc)
    result: dict[str, Any] = {
        "type": type(exc).__name__,
        "message_hash": stable_hash(message, hash_key),
        "message_size": len(message),
    }
    if capture_content:
        result["message"] = redact_text(message)
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


def _scalar_label(field_value: Any) -> str | None:
    # Governance context fields are scalar identifiers/labels. Skip nested
    # structures so request-body content is never stringified wholesale, and cap
    # length (audit H-13 / P3).
    if field_value is None or isinstance(field_value, (dict, list, tuple, set)):
        return None
    text = str(field_value)
    return text[:_MAX_CONTEXT_LEN] if len(text) > _MAX_CONTEXT_LEN else text


def infer_governance_context(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, str]:
    context: dict[str, str] = {}
    for value in (*args, *kwargs.values()):
        fields = object_to_mapping(value)
        for key in GOVERNANCE_CONTEXT_FIELDS:
            if key in context:
                continue
            label = _scalar_label(fields.get(key))
            if label is not None:
                context[key] = label
        # Never emit ``tenant_id`` (the platform routing key) from inferred app
        # data; record the app's own tenant under subject_tenant instead (H12).
        if _APP_TENANT_OUTPUT_KEY not in context:
            for tenant_field in _APP_TENANT_FIELDS:
                label = _scalar_label(fields.get(tenant_field))
                if label is not None:
                    context[_APP_TENANT_OUTPUT_KEY] = label
                    break
    return context

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

# patterns masked from captured content before it leaves the process; even with
# content capture on, common secrets and direct identifiers are replaced. kept
# conservative (high-signal patterns only) so ordinary prose isn't mangled
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[redacted-email]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[redacted-ssn]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[redacted-card]"),
    (re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9]{16,}\b"), "[redacted-key]"),
    (re.compile(r"\b[A-Za-z0-9_-]{40,}\b"), "[redacted-token]"),
)

# sentinel: value has no representable content, omit it entirely. never repr'd,
# which would leak object state like api keys on a config or client instance
_OMIT_CONTENT = object()


def redact_text(value: str) -> str:
    for pattern, replacement in _REDACTIONS:
        value = pattern.sub(replacement, value)
    return value


def _capture_content(value: Any) -> Any:
    """redacted json-native content, or _OMIT_CONTENT for anything else so objects aren't repr'd

    keys are redacted like values: a mapping keyed by an identifier ("MRN-1: ...")
    leaks through the key even when every value is handled
    """
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (list, tuple)):
        return [_capture_content(item) for item in value]
    if isinstance(value, dict):
        return {redact_text(str(key)): _capture_content(item) for key, item in value.items()}
    return _OMIT_CONTENT

GOVERNANCE_CONTEXT_FIELDS = {
    "user_id",
    "application_name",
    "use_case",
    "model_purpose",
}

# platform tenant comes from the ingestion key and is stamped server-side; never
# infer it from an app's request body (a mismatched tenant_id gets the whole batch
# rejected). record the app's own tenant under a non-colliding key instead
_APP_TENANT_FIELDS = ("tenant_id", "org_id", "organization_id", "account_id", "customer_id")
_APP_TENANT_OUTPUT_KEY = "subject_tenant"

# governance context values are identifiers/labels, not free-form content; cap
# length so a stray large field can't ride out under a governance label
_MAX_CONTEXT_LEN = 256


def _canonical_bytes(value: Any) -> bytes:
    """deterministic byte encoding for hashing; repr isn't stable so use sorted-key json for structured values"""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8", "replace")
    except Exception:
        return repr(value).encode("utf-8", "replace")


def stable_hash(value: Any, hash_key: str | None = None) -> str:
    """content fingerprint; with a hash_key it's an hmac so digests can't be linked across tenants"""
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
    """summarize an exception; message is content-derived (may hold pii) so hash it unless capture_content is on. type is always safe"""
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
    # scalar identifiers/labels only; skip nested structures so request bodies
    # aren't stringified wholesale, and cap length
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
        # never emit tenant_id (platform routing key) from inferred app data; use subject_tenant
        if _APP_TENANT_OUTPUT_KEY not in context:
            for tenant_field in _APP_TENANT_FIELDS:
                label = _scalar_label(fields.get(tenant_field))
                if label is not None:
                    context[_APP_TENANT_OUTPUT_KEY] = label
                    break
    return context


# metadata is app-supplied and can hold anything the caller passes in, so with
# content capture off it is treated as content rather than trusted. the keys the
# platform reads for inventory and control matching pass through (redacted and
# length-capped); every other key is reduced to a type+hash summary so the shape
# stays visible for debugging while the value never leaves the process. apps that
# need an extra label in the clear add it via config.metadata_allowlist
METADATA_SAFE_KEYS = frozenset(
    {
        *GOVERNANCE_CONTEXT_FIELDS,
        "workflow_name",
        "conversation_id",
        _APP_TENANT_OUTPUT_KEY,
        # explicitly passed tenant_id is the platform routing key the ingestion
        # endpoint checks the batch against, so it has to survive verbatim. this
        # is the caller declaring one, not the inference path above, which still
        # refuses to guess it from app objects
        "tenant_id",
    }
)


def _sanitize_mapping(
    mapping: dict[str, Any],
    safe_keys: frozenset[str],
    capture_content: bool,
    hash_key: str | None = None,
) -> dict[str, Any]:
    """one content boundary for every caller-supplied mapping

    with capture on the mapping passes through redacted; with capture off the
    keys named in safe_keys pass as redacted, length-capped labels and every
    other value becomes a type+hash summary. key names are content too — they
    are redacted and capped, so an identifier used as a key doesn't ride out
    """
    if capture_content:
        # content capture is an explicit opt-in; redact and pass through
        content = _capture_content(mapping)
        return content if isinstance(content, dict) else {}
    sanitized: dict[str, Any] = {}
    for key, value in mapping.items():
        name = redact_text(str(key))[:_MAX_CONTEXT_LEN]
        if name in safe_keys:
            label = _scalar_label(value)
            if label is not None:
                sanitized[name] = redact_text(label)
                continue
            # a safe key holding a structure is not a label; summarize it
        sanitized[name] = summarize_value(value, False, hash_key)
    return sanitized


def sanitize_metadata(
    metadata: dict[str, Any] | None,
    capture_content: bool,
    hash_key: str | None = None,
    allowlist: frozenset[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """governance-safe view of app metadata; see METADATA_SAFE_KEYS"""
    if not metadata:
        return {}
    safe_keys = METADATA_SAFE_KEYS if allowlist is None else METADATA_SAFE_KEYS | frozenset(allowlist)
    return _sanitize_mapping(metadata, safe_keys, capture_content, hash_key)


# an agent step is caller-structured; the platform reads only its labels (the
# tool name feeds the agent registry/posture) so those pass as labels and the
# step's inputs/outputs/observations obey the content boundary like a prompt.
# deliberately excludes "action": in common agent frameworks that field holds
# the agent's own free text, not a structural label
STEP_SAFE_KEYS = frozenset({"tool", "name", "type", "status"})

# a caller-supplied error payload: the platform reads event status, never the
# error body, so only type-shaped labels pass in the clear
ERROR_SAFE_KEYS = frozenset({"type", "code", "category"})


def sanitize_steps(
    steps: list[Any] | None,
    capture_content: bool,
    hash_key: str | None = None,
) -> list[Any]:
    """agent steps obey the content boundary; see STEP_SAFE_KEYS"""
    sanitized: list[Any] = []
    for step in steps or []:
        if isinstance(step, dict):
            sanitized.append(_sanitize_mapping(step, STEP_SAFE_KEYS, capture_content, hash_key))
        else:
            sanitized.append(summarize_value(step, capture_content, hash_key))
    return sanitized


# a guardrail rule id is a machine identifier (pii.ssn, mrn-pattern), not prose.
# shape is the only trustworthy distinction: redaction patterns can't recognize
# an arbitrary name or record number, but content is free text and identifiers
# aren't. anything with whitespace or beyond the id charset is treated as the
# matched content itself
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@-]{0,127}$")


def sanitize_rule_labels(
    rules: list[Any] | None,
    capture_content: bool,
    hash_key: str | None = None,
) -> list[str]:
    """matched guardrail rules pass as rule ids; anything else obeys the boundary

    with capture off only identifier-shaped entries pass in the clear — a
    guardrail library that surfaces the matched excerpt ("matched: Jane Q...")
    would otherwise carry content out under label treatment. with capture on
    entries pass redacted and capped like an incident title. a structured entry
    was never an id and becomes its digest either way
    """
    labels: list[str] = []
    for rule in rules or []:
        label = _scalar_label(rule)
        if label is None:
            labels.append(stable_hash(rule, hash_key))
        elif capture_content:
            labels.append(redact_text(label))
        elif _RULE_ID.match(label):
            labels.append(label)
        else:
            labels.append(stable_hash(label, hash_key))
    return labels


def sanitize_usage(
    usage: dict[str, Any] | None,
    capture_content: bool,
    hash_key: str | None = None,
    _depth: int = 0,
) -> dict[str, Any]:
    """usage is numeric accounting (token counts, costs)

    numbers pass through under redacted, capped keys; strings and other
    structures are summarized so the usage dict can't smuggle content past a
    capture_content=False install. nested numeric detail (provider token
    breakdowns) survives to a small depth
    """
    if not usage:
        return {}
    if capture_content:
        content = _capture_content(usage)
        return content if isinstance(content, dict) else {}
    sanitized: dict[str, Any] = {}
    for key, value in usage.items():
        name = redact_text(str(key))[:_MAX_CONTEXT_LEN]
        if value is None or isinstance(value, (bool, int, float)):
            sanitized[name] = value
        elif isinstance(value, dict) and _depth < 2:
            sanitized[name] = sanitize_usage(value, False, hash_key, _depth + 1)
        else:
            sanitized[name] = summarize_value(value, False, hash_key)
    return sanitized


def sanitize_error_payload(
    error: Any,
    capture_content: bool,
    hash_key: str | None = None,
) -> Any:
    """caller-supplied error payloads obey the content boundary

    mirrors summarize_error for raised exceptions: an error message is content
    (a failed lookup easily names the record it failed on), so it becomes a
    digest while type-shaped labels stay readable. see ERROR_SAFE_KEYS
    """
    if error is None:
        return None
    if not isinstance(error, dict):
        return summarize_value(error, capture_content, hash_key)
    return _sanitize_mapping(error, ERROR_SAFE_KEYS, capture_content, hash_key)

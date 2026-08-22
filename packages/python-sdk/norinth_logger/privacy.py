from __future__ import annotations

from hashlib import sha256
from typing import Any

GOVERNANCE_CONTEXT_FIELDS = {
    "tenant_id",
    "user_id",
    "application_name",
    "use_case",
    "model_purpose",
}


def stable_hash(value: Any) -> str:
    encoded = repr(value).encode("utf-8", errors="replace")
    return f"sha256:{sha256(encoded).hexdigest()}"


def summarize_value(value: Any, capture_content: bool) -> dict[str, Any]:
    if value is None:
        return {"type": "None", "is_none": True}

    summary: dict[str, Any] = {
        "type": type(value).__name__,
        "hash": stable_hash(value),
    }
    if isinstance(value, (str, bytes, list, tuple, dict, set)):
        summary["size"] = len(value)
    if capture_content:
        summary["content"] = value if isinstance(value, (str, int, float, bool, list, dict)) else repr(value)
    return summary


def summarize_call(args: tuple[Any, ...], kwargs: dict[str, Any], capture_content: bool) -> dict[str, Any]:
    return {
        "args": [summarize_value(arg, capture_content) for arg in args],
        "kwargs": {key: summarize_value(value, capture_content) for key, value in kwargs.items()},
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
            field_value = fields.get(key)
            if field_value is not None and key not in context:
                context[key] = str(field_value)
    return context

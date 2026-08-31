# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""map opentelemetry gen_ai spans to norinth events"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

SCHEMA_VERSION = "2026-01"

# gen_ai.operation.name -> event type
_OPERATION_TO_EVENT = {
    "chat": "model.call",
    "text_completion": "model.call",
    "generate_content": "model.call",
    "embeddings": "model.call",
    "execute_tool": "tool.call",
    "invoke_agent": "agent.run",
    "create_agent": "agent.run",
    "invoke_workflow": "agent.run",
    "retrieval": "retrieval.call",
}


class OtelPayloadError(ValueError):
    """the payload is not shaped like OTLP/HTTP JSON traces"""


def _as_list(value: Any, path: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise OtelPayloadError(f"{path} must be an array")
    return value


def _as_dict(value: Any, path: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise OtelPayloadError(f"{path} must be an object")
    return value


def _attr_value(value: dict[str, Any]) -> Any:
    """scalar from an otlp AnyValue"""
    for key in ("stringValue", "boolValue"):
        if key in value:
            return value[key]
    for key in ("intValue", "doubleValue"):
        if key in value:
            raw = value[key]
            try:
                return int(raw) if key == "intValue" else float(raw)
            except (TypeError, ValueError):
                return raw
    return value.get("stringValue")


def _attributes_to_dict(attributes: list[Any] | None) -> dict[str, Any]:
    """an attribute that is not a {key, value} pair is skipped, not fatal

    the envelope shape is the caller's contract and is enforced; one odd
    attribute inside an otherwise valid span is not worth rejecting a batch over
    """
    result: dict[str, Any] = {}
    for item in attributes or []:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        value = item.get("value")
        if key is not None and isinstance(value, dict):
            result[key] = _attr_value(value)
    return result


def _nanos_to_iso(nanos: Any) -> str:
    try:
        seconds = int(nanos) / 1_000_000_000
        return datetime.fromtimestamp(seconds, tz=UTC).isoformat()
    except (TypeError, ValueError):
        return datetime.now(UTC).isoformat()


def _event_type(operation: str | None, attrs: dict[str, Any]) -> str | None:
    if operation and operation in _OPERATION_TO_EVENT:
        return _OPERATION_TO_EVENT[operation]
    # a data-source id means retrieval even without an operation
    if attrs.get("gen_ai.data_source.id"):
        return "retrieval.call"
    return None


def _span_to_event(span: dict[str, Any], resource_attrs: dict[str, Any], path: str) -> dict[str, Any] | None:
    attrs = _attributes_to_dict(_as_list(span.get("attributes"), f"{path}.attributes"))
    operation = attrs.get("gen_ai.operation.name")
    event_type = _event_type(operation, attrs)
    if event_type is None:
        return None  # not a gen_ai span

    provider = attrs.get("gen_ai.provider.name") or attrs.get("gen_ai.system")
    model = attrs.get("gen_ai.request.model") or attrs.get("gen_ai.response.model")
    service = resource_attrs.get("service.name") or "otel"
    workflow_name = span.get("name") or operation or "otel-span"
    application_name = attrs.get("gen_ai.agent.name") or service

    metadata = {
        "application_name": application_name,
        "workflow_name": workflow_name,
    }
    if attrs.get("gen_ai.conversation.id"):
        metadata["conversation_id"] = attrs["gen_ai.conversation.id"]

    event_attributes: dict[str, Any] = {
        "provider": provider,
        "model": model,
        "operation": operation,
        "source": "otel",
        "usage": {
            "input_tokens": attrs.get("gen_ai.usage.input_tokens"),
            "output_tokens": attrs.get("gen_ai.usage.output_tokens"),
        },
        "metadata": metadata,
    }
    if event_type == "tool.call":
        event_attributes["tool_name"] = attrs.get("gen_ai.tool.name") or workflow_name
    if event_type == "agent.run":
        event_attributes["agent_name"] = attrs.get("gen_ai.agent.name") or workflow_name
        event_attributes["outcome"] = attrs.get("gen_ai.agent.outcome") or "observed"
        event_attributes["step_count"] = attrs.get("gen_ai.agent.step_count") or 0
    if event_type == "retrieval.call":
        event_attributes["retriever"] = attrs.get("gen_ai.data_source.id") or workflow_name

    error_type = attrs.get("error.type")
    status = "error" if error_type else "success"

    return {
        "type": event_type,
        "schema_version": SCHEMA_VERSION,
        "trace_id": str(span.get("traceId") or span.get("trace_id") or "otel"),
        "span_id": str(span.get("spanId") or span.get("span_id") or "otel"),
        "parent_span_id": span.get("parentSpanId"),
        "timestamp": _nanos_to_iso(span.get("endTimeUnixNano") or span.get("startTimeUnixNano")),
        "service": service,
        "environment": resource_attrs.get("deployment.environment") or "otel",
        "project": resource_attrs.get("service.namespace") or service,
        "name": workflow_name,
        "status": status,
        "attributes": event_attributes,
    }


def otel_spans_to_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """convert an otlp/http json traces payload into events; non-gen_ai spans skipped

    raises OtelPayloadError naming the offending path when the envelope is not
    shaped like OTLP. every level is checked because the sender is a third-party
    collector: an unchecked string here was iterated as characters, and the
    AttributeError that followed surfaced as a 500
    """
    events: list[dict[str, Any]] = []
    resource_spans = _as_list(payload.get("resourceSpans"), "resourceSpans")
    for outer, raw_resource_span in enumerate(resource_spans):
        resource_path = f"resourceSpans[{outer}]"
        resource_span = _as_dict(raw_resource_span, resource_path)
        resource = _as_dict(resource_span.get("resource"), f"{resource_path}.resource")
        resource_attrs = _attributes_to_dict(
            _as_list(resource.get("attributes"), f"{resource_path}.resource.attributes")
        )
        scope_spans = _as_list(resource_span.get("scopeSpans"), f"{resource_path}.scopeSpans")
        for middle, raw_scope_span in enumerate(scope_spans):
            scope_path = f"{resource_path}.scopeSpans[{middle}]"
            scope_span = _as_dict(raw_scope_span, scope_path)
            for inner, raw_span in enumerate(_as_list(scope_span.get("spans"), f"{scope_path}.spans")):
                span_path = f"{scope_path}.spans[{inner}]"
                event = _span_to_event(_as_dict(raw_span, span_path), resource_attrs, span_path)
                if event is not None:
                    events.append(event)
    return events

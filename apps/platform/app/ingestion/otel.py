"""Map OpenTelemetry GenAI spans to Norinth events.

Lets Norinth ingest telemetry from ANY OpenTelemetry-instrumented framework or
LLM gateway (LiteLLM, Portkey, Kong, Microsoft Agent Framework, Pydantic AI,
Vercel AI SDK, ...), not only the first-party SDK. This is the strategic
"consume everyone's signals" ingestion path from the GTM/research: build to the
GenAI semantic conventions so the observability layer feeds the governance
system of record.

Accepts OTLP/HTTP JSON (`resourceSpans -> scopeSpans -> spans`) and maps the
`gen_ai.*` attributes to the same event shapes the SDK emits, so the existing
entity/governance pipeline processes them unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

SCHEMA_VERSION = "2026-01"

# gen_ai.operation.name -> Norinth event type.
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


def _attr_value(value: dict[str, Any]) -> Any:
    """Extract a scalar from an OTLP AnyValue."""
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


def _attributes_to_dict(attributes: list[dict[str, Any]] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in attributes or []:
        key = item.get("key")
        if key is not None and "value" in item:
            result[key] = _attr_value(item["value"])
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
    # A span carrying a data-source id is a retrieval even without an operation.
    if attrs.get("gen_ai.data_source.id"):
        return "retrieval.call"
    return None


def _span_to_event(span: dict[str, Any], resource_attrs: dict[str, Any]) -> dict[str, Any] | None:
    attrs = _attributes_to_dict(span.get("attributes"))
    operation = attrs.get("gen_ai.operation.name")
    event_type = _event_type(operation, attrs)
    if event_type is None:
        return None  # not a GenAI span; skip

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
    """Convert an OTLP/HTTP JSON traces payload into Norinth events.

    Non-GenAI spans are silently skipped. The result feeds the same ingestion
    pipeline as first-party SDK events.
    """
    events: list[dict[str, Any]] = []
    for resource_span in payload.get("resourceSpans", []):
        resource_attrs = _attributes_to_dict((resource_span.get("resource") or {}).get("attributes"))
        for scope_span in resource_span.get("scopeSpans", []):
            for span in scope_span.get("spans", []):
                event = _span_to_event(span, resource_attrs)
                if event is not None:
                    events.append(event)
    return events

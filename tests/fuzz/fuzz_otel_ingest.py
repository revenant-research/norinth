#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research
"""fuzz the OTLP/HTTP JSON traces mapper

the OTLP ingestion route hands whatever a third-party collector sends to
otel_spans_to_events. the contract under test: any JSON document either maps
to a list of JSON-serializable events or raises OtelPayloadError naming the
offending path. any other exception would reach the collector as a 500.

inputs that start with "{" are parsed as JSON as-is, so the seed corpus and
libFuzzer's byte mutations exercise the parser boundary. every other input is
turned into an OTLP-shaped envelope by the fuzzed data provider, using the
gen_ai attribute keys the mapper reads, so mutations reach the span mapping
instead of dying in json.loads.

run (Linux, atheris installed):
  python tests/fuzz/fuzz_otel_ingest.py -max_total_time=60 tests/fuzz/corpus/otel
"""

from __future__ import annotations

import json
import pathlib
import sys

import atheris

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "apps" / "platform"))

with atheris.instrument_imports():
    from app.ingestion.otel import OtelPayloadError, otel_spans_to_events

EVENT_TYPES = {"model.call", "tool.call", "agent.run", "retrieval.call"}

ATTRIBUTE_KEYS = [
    "gen_ai.operation.name",
    "gen_ai.provider.name",
    "gen_ai.system",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.agent.name",
    "gen_ai.conversation.id",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.tool.name",
    "gen_ai.agent.outcome",
    "gen_ai.agent.step_count",
    "gen_ai.data_source.id",
    "error.type",
    "service.name",
    "service.namespace",
    "deployment.environment",
]
OPERATIONS = ["chat", "text_completion", "embeddings", "execute_tool", "invoke_agent", "retrieval", "unknown", ""]
VALUE_KINDS = ["stringValue", "boolValue", "intValue", "doubleValue", "arrayValue", "kvlistValue"]
SPAN_FIELDS = ("name", "traceId", "spanId", "parentSpanId", "startTimeUnixNano", "endTimeUnixNano")
MAX_DEPTH = 4


def _scalar(fdp: atheris.FuzzedDataProvider):
    choice = fdp.ConsumeIntInRange(0, 6)
    if choice == 0:
        return None
    if choice == 1:
        return fdp.ConsumeBool()
    if choice == 2:
        return fdp.ConsumeInt(8)
    if choice == 3:
        return fdp.ConsumeInt(64)  # far outside the range a timestamp can hold
    if choice == 4:
        return fdp.ConsumeFloat()  # includes nan and the infinities json.loads accepts
    if choice == 5:
        return fdp.PickValueInList(OPERATIONS)
    return fdp.ConsumeUnicodeNoSurrogates(32)


def _value(fdp: atheris.FuzzedDataProvider, depth: int = 0):
    """any JSON value, biased toward scalars"""
    if depth >= MAX_DEPTH or fdp.ConsumeBool():
        return _scalar(fdp)
    if fdp.ConsumeBool():
        return [_value(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    return {fdp.ConsumeUnicodeNoSurrogates(8): _value(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3))}


def _junk_here(fdp: atheris.FuzzedDataProvider) -> bool:
    return fdp.ConsumeIntInRange(0, 7) == 0


def _attribute(fdp: atheris.FuzzedDataProvider):
    if _junk_here(fdp):
        return _value(fdp)
    key = fdp.PickValueInList(ATTRIBUTE_KEYS) if fdp.ConsumeBool() else _value(fdp)
    if _junk_here(fdp):
        return {"key": key, "value": _value(fdp)}
    return {"key": key, "value": {fdp.PickValueInList(VALUE_KINDS): _value(fdp)}}


def _attributes(fdp: atheris.FuzzedDataProvider):
    if _junk_here(fdp):
        return _value(fdp)
    return [_attribute(fdp) for _ in range(fdp.ConsumeIntInRange(0, 6))]


def _span(fdp: atheris.FuzzedDataProvider):
    if _junk_here(fdp):
        return _value(fdp)
    span: dict = {"attributes": _attributes(fdp)}
    for field in SPAN_FIELDS:
        if fdp.ConsumeBool():
            span[field] = _value(fdp)
    return span


def _payload(fdp: atheris.FuzzedDataProvider):
    if _junk_here(fdp):
        return _value(fdp)
    resource_spans: list = []
    for _ in range(fdp.ConsumeIntInRange(0, 2)):
        if _junk_here(fdp):
            resource_spans.append(_value(fdp))
            continue
        scope_spans: list = []
        for _ in range(fdp.ConsumeIntInRange(0, 2)):
            if _junk_here(fdp):
                scope_spans.append(_value(fdp))
                continue
            scope_spans.append({"spans": [_span(fdp) for _ in range(fdp.ConsumeIntInRange(0, 3))]})
        resource_spans.append({"resource": {"attributes": _attributes(fdp)}, "scopeSpans": scope_spans})
    return {"resourceSpans": resource_spans}


def _check(payload) -> None:
    if not isinstance(payload, dict):
        return  # the route rejects non-object bodies before the mapper sees them
    try:
        events = otel_spans_to_events(payload)
    except OtelPayloadError:
        return
    json.dumps(events)  # the route stores and re-serializes events; nothing unserializable may come out
    for event in events:
        assert event["type"] in EVENT_TYPES, event
        assert isinstance(event["timestamp"], str), event


def test_one_input(data: bytes) -> None:
    if data[:1] == b"{":
        try:
            payload = json.loads(data)
        except (ValueError, RecursionError):
            return
        _check(payload)
        return
    _check(_payload(atheris.FuzzedDataProvider(data)))


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

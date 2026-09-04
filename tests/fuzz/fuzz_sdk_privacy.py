#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research
"""fuzz the SDK content boundary

every caller-supplied structure the SDK emits crosses privacy.py before it
leaves the process. the contract under test, for any input shape, either
content-capture setting, and with or without a fingerprint key:

  * the sanitizers never raise
  * their output serializes the way the transport serializes a batch
  * a secret planted as a whole value, mapping key, list item, rule label, or
    error message never appears in the output. with content capture off only
    labels leave the process; with it on the redaction patterns replace it

run (Linux, atheris installed):
  python tests/fuzz/fuzz_sdk_privacy.py -max_total_time=60
"""

from __future__ import annotations

import json
import pathlib
import sys

import atheris

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packages" / "python-sdk"))

with atheris.instrument_imports():
    from norinth_logger.privacy import (
        infer_governance_context,
        redact_text,
        sanitize_error_payload,
        sanitize_metadata,
        sanitize_rule_labels,
        sanitize_steps,
        sanitize_usage,
        summarize_call,
        summarize_error,
        summarize_value,
    )

# one of each shape the redaction patterns exist for. planted whole, never as a
# substring, because the patterns are word-bounded on purpose
SECRETS = [
    "alice.doe@example.com",
    "123-45-6789",
    "4111 1111 1111 1111",
    "sk-live0123456789abcdefXYZ",
    "ghp" + "A1" * 22,
]
KEYS = [
    "user_id",
    "application_name",
    "use_case",
    "model_purpose",
    "workflow_name",
    "conversation_id",
    "tenant_id",
    "org_id",
    "subject_tenant",
    "tool",
    "name",
    "type",
    "status",
    "action",
    "code",
    "category",
    "message",
    "input_tokens",
    "output_tokens",
    "prompt",
    "extra",
]
LABELS = ["chat", "pii.ssn", "mrn-pattern", "lookup", "ok", "TimeoutError", ""]
MAX_DEPTH = 3


def _scalar(fdp: atheris.FuzzedDataProvider, planted: list[str]):
    choice = fdp.ConsumeIntInRange(0, 8)
    if choice == 0:
        return None
    if choice == 1:
        return fdp.ConsumeBool()
    if choice == 2:
        return fdp.ConsumeInt(8)
    if choice == 3:
        return fdp.ConsumeFloat()
    if choice == 4:
        return fdp.ConsumeBytes(8)
    if choice == 5:
        return fdp.PickValueInList(LABELS)
    if choice <= 7:
        secret = fdp.PickValueInList(SECRETS)
        planted.append(secret)
        return secret
    return fdp.ConsumeUnicodeNoSurrogates(24)


def _key(fdp: atheris.FuzzedDataProvider, planted: list[str]) -> str:
    choice = fdp.ConsumeIntInRange(0, 3)
    if choice == 0:
        secret = fdp.PickValueInList(SECRETS)
        planted.append(secret)
        return secret
    if choice == 1:
        return fdp.ConsumeUnicodeNoSurrogates(12)
    return fdp.PickValueInList(KEYS)


def _value(fdp: atheris.FuzzedDataProvider, planted: list[str], depth: int = 0):
    if depth >= MAX_DEPTH or fdp.ConsumeBool():
        return _scalar(fdp, planted)
    choice = fdp.ConsumeIntInRange(0, 3)
    size = fdp.ConsumeIntInRange(0, 3)
    if choice == 0:
        return [_value(fdp, planted, depth + 1) for _ in range(size)]
    if choice == 1:
        return tuple(_value(fdp, planted, depth + 1) for _ in range(size))
    if choice == 2:
        return {s for s in (_scalar(fdp, planted) for _ in range(size)) if isinstance(s, str | int | bool | None)}
    return _mapping(fdp, planted, depth + 1)


def _mapping(fdp: atheris.FuzzedDataProvider, planted: list[str], depth: int = 0) -> dict:
    return {_key(fdp, planted): _value(fdp, planted, depth) for _ in range(fdp.ConsumeIntInRange(0, 4))}


def _serialize(value) -> str:
    # the transport serializes a batch with default=str; anything the sanitizers
    # emit must survive that the same way
    return json.dumps(value, default=str)


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    capture = fdp.ConsumeBool()
    hash_key = "fingerprint-key" if fdp.ConsumeBool() else None
    allowlist = ("extra",) if fdp.ConsumeBool() else None
    planted: list[str] = []

    metadata = _mapping(fdp, planted)
    steps = [_value(fdp, planted) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    rules = [_value(fdp, planted) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    usage = _mapping(fdp, planted)
    error = _value(fdp, planted)
    args = tuple(_value(fdp, planted) for _ in range(fdp.ConsumeIntInRange(0, 2)))
    kwargs = {"payload": _value(fdp, planted)}
    message = _scalar(fdp, planted)

    outputs = [
        sanitize_metadata(metadata, capture, hash_key, allowlist),
        sanitize_steps(steps, capture, hash_key),
        sanitize_rule_labels(rules, capture, hash_key),
        sanitize_usage(usage, capture, hash_key),
        sanitize_error_payload(error, capture, hash_key),
        summarize_value(error, capture, hash_key),
        summarize_error(ValueError(message), capture, hash_key),
        summarize_call(args, kwargs, capture, hash_key),
        redact_text(str(message)),
    ]
    wire = _serialize(outputs)
    for secret in planted:
        assert secret not in wire, f"{secret!r} left the process (capture_content={capture})"

    # governance context is label extraction; it must not raise and must emit
    # only capped strings
    context = infer_governance_context(args, kwargs)
    _serialize(context)
    for label in context.values():
        assert isinstance(label, str) and len(label) <= 256, context


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

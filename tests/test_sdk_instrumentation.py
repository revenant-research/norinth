"""Tests for SDK auto-instrumentation coverage (audit H-14, A1/A2/A5).

The provider patchers are exercised against fake resource classes, so no real
OpenAI/Anthropic SDK or network call is needed — the point is the wrapper
behavior: sync and async calls both emit a model.call AFTER the underlying call
resolves, errors are captured, and usage is normalized across naming schemes.
"""

from __future__ import annotations

import asyncio
import importlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

autoinstrument = importlib.import_module("norinth_logger.autoinstrument")


class _CapturingClient:
    """Minimal stand-in for NorinthClient that records model_call invocations."""

    def __init__(self):
        from norinth_logger.config import NorinthConfig

        self.config = NorinthConfig(api_key="t", async_transport=False)
        self.calls: list[dict] = []

    def model_call(self, **kwargs):
        self.calls.append(kwargs)


class _Usage:
    # chat.completions naming, which the old normalizer dropped.
    prompt_tokens = 11
    completion_tokens = 7
    total_tokens = 18


class _Response:
    model = "gpt-4o"
    usage = _Usage()


def test_sync_completion_is_instrumented_and_usage_normalized():
    class FakeCompletions:
        def create(self, **kwargs):
            return _Response()

    client = _CapturingClient()
    autoinstrument.patch_provider_method(
        patch_key="test.sync.create",
        owner=FakeCompletions,
        method_name="create",
        provider="openai",
        operation="chat.completions.create",
        prompt_getter=lambda a, k: k.get("messages"),
        client=client,
    )

    result = FakeCompletions().create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
    assert isinstance(result, _Response)
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["provider"] == "openai"
    assert call["operation"] == "chat.completions.create"
    assert call["status"] == "success"
    # chat.completions naming mapped to input/output tokens (audit A5).
    assert call["usage"]["input_tokens"] == 11
    assert call["usage"]["output_tokens"] == 7


def test_async_completion_records_only_after_await():
    order: list[str] = []

    class FakeAsyncCompletions:
        async def create(self, **kwargs):
            await asyncio.sleep(0)
            order.append("call-ran")
            return _Response()

    client = _CapturingClient()
    autoinstrument.patch_provider_method_async(
        patch_key="test.async.create",
        owner=FakeAsyncCompletions,
        method_name="create",
        provider="openai",
        operation="chat.completions.create",
        prompt_getter=lambda a, k: k.get("messages"),
        client=client,
    )

    async def run():
        return await FakeAsyncCompletions().create(messages=[])

    result = asyncio.run(run())
    assert isinstance(result, _Response)
    # The model.call is emitted AFTER the coroutine actually ran (not before).
    assert order == ["call-ran"]
    assert len(client.calls) == 1
    assert client.calls[0]["status"] == "success"


def test_error_is_captured_and_reraised():
    class FakeErroring:
        def create(self, **kwargs):
            raise ValueError("boom with secret 123-45-6789")

    client = _CapturingClient()
    autoinstrument.patch_provider_method(
        patch_key="test.err.create",
        owner=FakeErroring,
        method_name="create",
        provider="openai",
        operation="chat.completions.create",
        prompt_getter=lambda a, k: None,
        client=client,
    )

    try:
        FakeErroring().create()
        raise AssertionError("expected the original exception to propagate")
    except ValueError:
        pass

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["status"] == "error"
    # The error message is summarized, not emitted raw (ties to H-13).
    assert "message" not in call["error"]
    assert call["error"]["type"] == "ValueError"

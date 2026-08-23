"""norinth.wrap() instruments model calls without breaking the client"""

from __future__ import annotations

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from norinth_logger.wrappers import wrap_client  # noqa: E402


class _CapturingClient:
    def __init__(self):
        from norinth_logger.config import NorinthConfig

        self.config = NorinthConfig(api_key="t", async_transport=False)
        self.calls: list[dict] = []

    def model_call(self, **kwargs):
        self.calls.append(kwargs)


class _Usage:
    input_tokens = 3
    output_tokens = 5


class _Response:
    model = "gpt-4o"
    usage = _Usage()


class _Completions:
    def create(self, **kwargs):
        return _Response()


class _Chat:
    def __init__(self):
        self.completions = _Completions()


class _Files:
    def create(self, **kwargs):
        return {"id": "file-1"}


class _FakeOpenAI:
    def __init__(self):
        self.chat = _Chat()
        self.files = _Files()
        self.closed = False
        self.entered = False

    def close(self):
        self.closed = True
        return "closed"

    def with_options(self, **kwargs):
        return _FakeOpenAI()

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False


def test_model_operation_is_instrumented():
    cap = _CapturingClient()
    client = wrap_client(_FakeOpenAI(), cap)
    result = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
    assert isinstance(result, _Response)
    assert len(cap.calls) == 1
    assert cap.calls[0]["operation"] == "chat.completions.create"
    assert cap.calls[0]["usage"]["input_tokens"] == 3


def test_non_model_create_is_not_recorded():
    cap = _CapturingClient()
    client = wrap_client(_FakeOpenAI(), cap)
    out = client.files.create(purpose="fine-tune")
    assert out == {"id": "file-1"}
    # files.create is not a model completion; it must not emit a model.call
    assert cap.calls == []


def test_close_passes_through():
    cap = _CapturingClient()
    raw = _FakeOpenAI()
    client = wrap_client(raw, cap)
    assert client.close() == "closed"
    assert raw.closed is True


def test_with_options_returns_usable_client():
    cap = _CapturingClient()
    client = wrap_client(_FakeOpenAI(), cap)
    # with_options must not raise; it returns a working raw client
    other = client.with_options(timeout=5)
    assert isinstance(other, _FakeOpenAI)


def test_context_manager_delegates():
    cap = _CapturingClient()
    raw = _FakeOpenAI()
    with wrap_client(raw, cap) as client:
        assert client.chat.completions.create(model="m", messages=[]) is not None
    assert raw.entered is True
    assert raw.closed is True


def test_async_call_records_after_await():
    order: list[str] = []

    class _AsyncCompletions:
        async def create(self, **kwargs):
            await asyncio.sleep(0)
            order.append("ran")
            return _Response()

    class _AsyncChat:
        def __init__(self):
            self.completions = _AsyncCompletions()

    class _AsyncClient:
        def __init__(self):
            self.chat = _AsyncChat()

    cap = _CapturingClient()
    client = wrap_client(_AsyncClient(), cap)

    async def run():
        return await client.chat.completions.create(messages=[])

    result = asyncio.run(run())
    assert isinstance(result, _Response)
    assert order == ["ran"]  # not recorded before the await
    assert len(cap.calls) == 1
    assert cap.calls[0]["status"] == "success"
    assert cap.calls[0]["duration_ms"] >= 0


def test_streaming_call_does_not_fabricate_usage_or_hash_stream():
    class _Stream:
        def __iter__(self):
            return iter([])

    class _StreamingCompletions:
        def create(self, **kwargs):
            return _Stream()

    class _StreamChat:
        def __init__(self):
            self.completions = _StreamingCompletions()

    class _StreamClient:
        def __init__(self):
            self.chat = _StreamChat()

    cap = _CapturingClient()
    client = wrap_client(_StreamClient(), cap)
    stream = client.chat.completions.create(model="gpt-4o", messages=[], stream=True)
    assert hasattr(stream, "__iter__")
    call = cap.calls[0]
    assert call["usage"] == {}
    assert call["response"] is None  # un-consumed stream is never summarized
    assert call["metadata"] == {"streaming": True}

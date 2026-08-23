from __future__ import annotations

import inspect
from collections.abc import Callable
from time import perf_counter
from typing import Any

from .client import NorinthClient
from .privacy import summarize_error

# Only these operations generate a model completion and should be recorded as
# model.call events. Restricting by full path keeps non-generative operations
# under the same clients — files.create, batches.create, fine_tuning.jobs.create,
# vector_stores.create — from being mislabelled as model calls (audit H14).
_MODEL_OPERATION_PATHS = {
    "chat.completions.create",
    "completions.create",
    "messages.create",
    "messages.stream",
    "responses.create",
    "responses.stream",
    "embeddings.create",
}
# Framework-level entry points (LangChain, LlamaIndex) that are model calls
# wherever they appear, addressed by method name rather than a resource path.
_MODEL_OPERATION_NAMES = {"invoke", "ainvoke", "predict", "apredict", "complete", "acomplete"}


def normalize_usage(usage: Any) -> dict[str, Any]:
    """Normalize provider usage objects to input/output/total token counts.

    Handles both the Responses/Anthropic naming (input_tokens/output_tokens) and
    the chat.completions naming (prompt_tokens/completion_tokens), plus cached and
    reasoning token detail when present (audit A5).
    """
    if usage is None:
        return {}
    if isinstance(usage, dict):
        return usage
    usage_values: dict[str, Any] = {}

    def read(*names: str) -> Any:
        for name in names:
            value = getattr(usage, name, None)
            if value is not None:
                return value
        return None

    input_tokens = read("input_tokens", "prompt_tokens")
    output_tokens = read("output_tokens", "completion_tokens")
    total_tokens = read("total_tokens")
    if input_tokens is not None:
        usage_values["input_tokens"] = input_tokens
    if output_tokens is not None:
        usage_values["output_tokens"] = output_tokens
    if total_tokens is not None:
        usage_values["total_tokens"] = total_tokens

    # Optional detail: Anthropic cache tokens, OpenAI cached/reasoning tokens.
    for field in ("cache_read_input_tokens", "cache_creation_input_tokens"):
        value = getattr(usage, field, None)
        if value is not None:
            usage_values[field] = value

    return usage_values or getattr(usage, "__dict__", {})


class WrappedCallable:
    """Instruments a single model operation, synchronous or asynchronous.

    A coroutine function is awaited before the event is recorded, so an async
    model call is no longer logged as an instant zero-token success (audit H14).
    A streaming call (``stream=True``) is recorded as a completion without
    fabricated usage or a hash of the un-consumed stream object.
    """

    def __init__(self, target: Callable[..., Any], client: NorinthClient, provider: str, operation: str) -> None:
        self._target = target
        self._client = client
        self._provider = provider
        self._operation = operation

    def __call__(self, *args: Any, **kwargs: Any):
        if inspect.iscoroutinefunction(self._target):
            return self._async_call(args, kwargs)
        started = perf_counter()
        try:
            response = self._target(*args, **kwargs)
        except Exception as exc:
            self._record(None, kwargs, started, "error", exc)
            raise
        if inspect.isawaitable(response):
            # Target wasn't a declared coroutine function but returned an
            # awaitable; instrument the awaited value instead of "now".
            return self._await_and_record(response, kwargs, started)
        self._record(response, kwargs, started, "success", None)
        return response

    async def _async_call(self, args: tuple[Any, ...], kwargs: dict[str, Any]):
        started = perf_counter()
        try:
            response = await self._target(*args, **kwargs)
        except Exception as exc:
            self._record(None, kwargs, started, "error", exc)
            raise
        self._record(response, kwargs, started, "success", None)
        return response

    async def _await_and_record(self, awaitable: Any, kwargs: dict[str, Any], started: float):
        try:
            response = await awaitable
        except Exception as exc:
            self._record(None, kwargs, started, "error", exc)
            raise
        self._record(response, kwargs, started, "success", None)
        return response

    def _record(self, response: Any, kwargs: dict[str, Any], started: float, status: str, exc: BaseException | None) -> None:
        duration_ms = (perf_counter() - started) * 1000
        error = (
            summarize_error(exc, self._client.config.capture_content, self._client.config.signing_secret)
            if exc is not None
            else None
        )
        streaming = bool(kwargs.get("stream"))
        model = str(getattr(response, "model", None) or kwargs.get("model") or "unknown")
        prompt = kwargs.get("input") or kwargs.get("prompt") or kwargs.get("messages")
        # A streaming response is a not-yet-consumed iterator; hashing it would
        # fingerprint a memory address and its usage is unknown until drained, so
        # record neither rather than emitting misleading values.
        self._client.model_call(
            provider=self._provider,
            model=model,
            operation=self._operation,
            prompt=prompt,
            response=None if streaming else response,
            usage={} if streaming else normalize_usage(getattr(response, "usage", None)),
            metadata={"streaming": True} if streaming else None,
            status=status,
            duration_ms=duration_ms,
            error=error,
        )


def _is_model_operation(path: str, name: str) -> bool:
    return path in _MODEL_OPERATION_PATHS or name in _MODEL_OPERATION_NAMES


class ClientProxy:
    """Transparent proxy that instruments model operations and passes through
    everything else untouched.

    The previous proxy wrapped *every* callable and attribute, which turned
    ``client.close()``, ``client.with_options(...)`` and the context-manager
    protocol into ``ClientProxy`` objects that raised when called (audit H14).
    Now only genuine model operations are wrapped; all other methods and values
    are returned verbatim, and the context-manager and async-context-manager
    protocols delegate to the wrapped client.
    """

    def __init__(self, target: Any, client: NorinthClient, path: str = "") -> None:
        self._target = target
        self._client = client
        self._path = path

    def __getattr__(self, name: str):
        if name.startswith("_"):
            return getattr(self._target, name)
        value = getattr(self._target, name)
        path = f"{self._path}.{name}" if self._path else name
        if callable(value):
            if _is_model_operation(path, name):
                provider = type(self._target).__module__.split(".")[0]
                return WrappedCallable(value, self._client, provider=provider, operation=path)
            # A bound method, factory (with_options), or lifecycle call
            # (close/aclose): return it untouched so the client keeps working.
            return value
        # A nested resource namespace (client.chat, chat.completions) — recurse
        # so operations underneath it are reachable and instrumentable. Plain
        # scalar/collection attributes are returned as-is.
        if hasattr(value, "__dict__") and not isinstance(value, (str, bytes, bytearray)):
            return ClientProxy(value, self._client, path=path)
        return value

    # Preserve the wrapped client's (async) context-manager behaviour.
    def __enter__(self):
        self._target.__enter__()
        return self

    def __exit__(self, *exc: Any):
        return self._target.__exit__(*exc)

    async def __aenter__(self):
        await self._target.__aenter__()
        return self

    async def __aexit__(self, *exc: Any):
        return await self._target.__aexit__(*exc)


def wrap_client(client: Any, norinth_client: NorinthClient):
    return ClientProxy(client, norinth_client)

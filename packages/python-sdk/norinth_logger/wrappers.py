from __future__ import annotations

from collections.abc import Callable
from time import perf_counter
from typing import Any

from .client import NorinthClient


def normalize_usage(usage: Any) -> dict[str, Any]:
    if usage is None:
        return {}
    if isinstance(usage, dict):
        return usage
    usage_values: dict[str, Any] = {}
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        value = getattr(usage, field, None)
        if value is not None:
            usage_values[field] = value
    if usage_values:
        return usage_values
    return getattr(usage, "__dict__", {})


class WrappedCallable:
    def __init__(self, target: Callable[..., Any], client: NorinthClient, provider: str, operation: str) -> None:
        self._target = target
        self._client = client
        self._provider = provider
        self._operation = operation

    def __call__(self, *args: Any, **kwargs: Any):
        started = perf_counter()
        status = "success"
        error: dict[str, Any] | None = None
        response = None
        try:
            response = self._target(*args, **kwargs)
            return response
        except Exception as exc:
            status = "error"
            error = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000
            model = str(getattr(response, "model", None) or kwargs.get("model") or "unknown")
            prompt = kwargs.get("input") or kwargs.get("prompt") or kwargs.get("messages")
            self._client.model_call(
                provider=self._provider,
                model=model,
                operation=self._operation,
                prompt=prompt,
                response=response,
                usage=normalize_usage(getattr(response, "usage", None)),
                status=status,
                duration_ms=duration_ms,
                error=error,
            )


class ClientProxy:
    def __init__(self, target: Any, client: NorinthClient, path: str = "") -> None:
        self._target = target
        self._client = client
        self._path = path

    def __getattr__(self, name: str):
        value = getattr(self._target, name)
        path = f"{self._path}.{name}" if self._path else name
        if callable(value) and name in {"create", "invoke", "predict", "complete"}:
            provider = self._target.__class__.__module__.split(".")[0]
            return WrappedCallable(value, self._client, provider=provider, operation=path)
        if name.startswith("_"):
            return value
        return ClientProxy(value, self._client, path=path) if hasattr(value, "__dict__") else value


def wrap_client(client: Any, norinth_client: NorinthClient):
    return ClientProxy(client, norinth_client)

from __future__ import annotations

import json
from collections.abc import Callable
from time import perf_counter
from typing import Any

from .context import TraceContext, reset_context, set_context
from .privacy import infer_governance_context, summarize_error
from .schemas import NorinthEvent, new_id
from .wrappers import normalize_usage

_PATCHED: set[str] = set()


def autoinstrument(client) -> None:
    instrument_openai(client)
    instrument_anthropic(client)


def _openai_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    return kwargs.get("input") or kwargs.get("prompt")


def _messages(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    return kwargs.get("messages")


def instrument_openai(client) -> None:
    # Responses API (sync + async).
    try:
        from openai.resources.responses.responses import Responses

        patch_provider_method(
            patch_key="openai.responses.create",
            owner=Responses,
            method_name="create",
            provider="openai",
            operation="responses.create",
            prompt_getter=_openai_input,
            client=client,
        )
    except Exception:
        pass
    try:
        from openai.resources.responses.responses import AsyncResponses

        patch_provider_method_async(
            patch_key="openai.responses.acreate",
            owner=AsyncResponses,
            method_name="create",
            provider="openai",
            operation="responses.create",
            prompt_getter=_openai_input,
            client=client,
        )
    except Exception:
        pass
    # Chat Completions API — the most widely used OpenAI surface (sync + async).
    # Previously uninstrumented, so this traffic was invisible (audit A1/H-14).
    try:
        from openai.resources.chat.completions import AsyncCompletions, Completions

        patch_provider_method(
            patch_key="openai.chat.completions.create",
            owner=Completions,
            method_name="create",
            provider="openai",
            operation="chat.completions.create",
            prompt_getter=_messages,
            client=client,
        )
        patch_provider_method_async(
            patch_key="openai.chat.completions.acreate",
            owner=AsyncCompletions,
            method_name="create",
            provider="openai",
            operation="chat.completions.create",
            prompt_getter=_messages,
            client=client,
        )
    except Exception:
        pass


def instrument_anthropic(client) -> None:
    # Messages API (sync + async).
    try:
        from anthropic.resources.messages.messages import Messages

        patch_provider_method(
            patch_key="anthropic.messages.create",
            owner=Messages,
            method_name="create",
            provider="anthropic",
            operation="messages.create",
            prompt_getter=_messages,
            client=client,
        )
    except Exception:
        pass
    try:
        from anthropic.resources.messages.messages import AsyncMessages

        patch_provider_method_async(
            patch_key="anthropic.messages.acreate",
            owner=AsyncMessages,
            method_name="create",
            provider="anthropic",
            operation="messages.create",
            prompt_getter=_messages,
            client=client,
        )
    except Exception:
        pass


def patch_provider_method(
    *,
    patch_key: str,
    owner: type,
    method_name: str,
    provider: str,
    operation: str,
    prompt_getter: Callable[[tuple[Any, ...], dict[str, Any]], Any],
    client,
) -> None:
    if patch_key in _PATCHED:
        return

    original = getattr(owner, method_name)

    def instrumented(self, *args: Any, **kwargs: Any):
        started = perf_counter()
        response = None
        status = "success"
        error: dict[str, Any] | None = None
        try:
            response = original(self, *args, **kwargs)
            return response
        except Exception as exc:
            status = "error"
            error = summarize_error(exc, client.config.capture_content, client.config.signing_secret)
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000
            model = str(getattr(response, "model", None) or kwargs.get("model") or "unknown")
            client.model_call(
                provider=provider,
                model=model,
                operation=operation,
                prompt=prompt_getter(args, kwargs),
                response=response,
                usage=normalize_usage(getattr(response, "usage", None)),
                status=status,
                duration_ms=duration_ms,
                error=error,
            )

    setattr(owner, method_name, instrumented)
    _PATCHED.add(patch_key)


def patch_provider_method_async(
    *,
    patch_key: str,
    owner: type,
    method_name: str,
    provider: str,
    operation: str,
    prompt_getter: Callable[[tuple[Any, ...], dict[str, Any]], Any],
    client,
) -> None:
    """Async counterpart to patch_provider_method.

    The wrapper awaits the real coroutine and records the model call only after
    it resolves, so async provider calls are captured correctly instead of being
    logged as instant success before they run (audit A2/H-14).
    """
    if patch_key in _PATCHED:
        return

    original = getattr(owner, method_name)

    async def instrumented(self, *args: Any, **kwargs: Any):
        started = perf_counter()
        response = None
        status = "success"
        error: dict[str, Any] | None = None
        try:
            response = await original(self, *args, **kwargs)
            return response
        except Exception as exc:
            status = "error"
            error = summarize_error(exc, client.config.capture_content, client.config.signing_secret)
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000
            model = str(getattr(response, "model", None) or kwargs.get("model") or "unknown")
            client.model_call(
                provider=provider,
                model=model,
                operation=operation,
                prompt=prompt_getter(args, kwargs),
                response=response,
                usage=normalize_usage(getattr(response, "usage", None)),
                status=status,
                duration_ms=duration_ms,
                error=error,
            )

    setattr(owner, method_name, instrumented)
    _PATCHED.add(patch_key)


_BODY_INFERENCE_CAP = 64 * 1024  # bytes of request body buffered for context inference


class NorinthFastAPIMiddleware:
    def __init__(self, app, client, *, system: str = "fastapi") -> None:
        self.app = app
        self.client = client
        self.system = system

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Buffer only enough of the request body to infer governance context, then
        # replay what we read and DELEGATE the rest of receive() to the real
        # transport. Returning a synthetic request forever (the old behaviour)
        # starves Starlette's disconnect listener, which polls receive() while a
        # StreamingResponse is open -> the worker spins at 100% CPU and never
        # completes (finding C8). Delegating also bounds memory for large uploads.
        body = b""
        buffered: list[dict] = []
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request":
                break
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
            if len(body) > _BODY_INFERENCE_CAP:
                break  # stop buffering; the rest streams straight to the app

        async def replay_receive():
            if buffered:
                return buffered.pop(0)
            return await receive()

        # Capture the response status so 4xx/5xx are not recorded as success.
        response_status = {"code": None}

        async def wrapped_send(event):
            if event.get("type") == "http.response.start":
                response_status["code"] = event.get("status")
            await send(event)

        workflow_name = workflow_name_from_path(scope.get("path", ""))
        metadata = infer_governance_context((decode_body(body),), {})
        metadata["workflow_name"] = workflow_name
        context = TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"), system=self.system, metadata=metadata)
        token = set_context(context)
        started = perf_counter()
        status = "success"
        error_summary = None
        try:
            await self.app(scope, replay_receive, wrapped_send)
        except Exception as exc:
            status = "error"
            error_summary = summarize_error(exc, self.client.config.capture_content, self.client.config.signing_secret)
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000
            code = response_status["code"]
            if status != "error" and isinstance(code, int) and code >= 500:
                status = "error"  # a 5xx response is a failed request, not a success
            self.client.record(
                NorinthEvent(
                    type="trace.completed",
                    trace_id=context.trace_id,
                    span_id=context.span_id,
                    service=self.client.config.service,
                    environment=self.client.config.environment,
                    project=self.client.config.project,
                    system=context.system,
                    name=workflow_name,
                    status=status,
                    duration_ms=duration_ms,
                    attributes={"metadata": context.metadata, "error": error_summary, "http_status": code},
                )
            )
            reset_context(token)


def decode_body(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    try:
        decoded = json.loads(body.decode("utf-8"))
        return decoded if isinstance(decoded, dict) else {}
    except Exception:
        return {}


def workflow_name_from_path(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    if not parts:
        return "root"
    return parts[-1].replace("-", ".")

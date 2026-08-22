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


def instrument_openai(client) -> None:
    try:
        from openai.resources.responses.responses import Responses
    except Exception:
        return
    patch_provider_method(
        patch_key="openai.responses.create",
        owner=Responses,
        method_name="create",
        provider="openai",
        operation="responses.create",
        prompt_getter=lambda args, kwargs: kwargs.get("input") or kwargs.get("prompt"),
        client=client,
    )


def instrument_anthropic(client) -> None:
    try:
        from anthropic.resources.messages.messages import Messages
    except Exception:
        return
    patch_provider_method(
        patch_key="anthropic.messages.create",
        owner=Messages,
        method_name="create",
        provider="anthropic",
        operation="messages.create",
        prompt_getter=lambda args, kwargs: kwargs.get("messages"),
        client=client,
    )


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


class NorinthFastAPIMiddleware:
    def __init__(self, app, client, *, system: str = "fastapi") -> None:
        self.app = app
        self.client = client
        self.system = system

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body = b""
        more_body = True
        messages = []
        while more_body:
            message = await receive()
            messages.append(message)
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        async def replay_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        workflow_name = workflow_name_from_path(scope.get("path", ""))
        metadata = infer_governance_context((decode_body(body),), {})
        metadata["workflow_name"] = workflow_name
        context = TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"), system=self.system, metadata=metadata)
        token = set_context(context)
        started = perf_counter()
        status = "success"
        error_summary = None
        try:
            await self.app(scope, replay_receive, send)
        except Exception as exc:
            status = "error"
            error_summary = summarize_error(exc, self.client.config.capture_content, self.client.config.signing_secret)
            raise
        finally:
            duration_ms = (perf_counter() - started) * 1000
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
                    attributes={"metadata": context.metadata, "error": error_summary},
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

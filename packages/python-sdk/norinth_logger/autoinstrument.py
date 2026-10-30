# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from time import perf_counter
from typing import Any

from .context import TraceContext, reset_context, set_context
from .privacy import infer_governance_context, sanitize_metadata, summarize_error
from .schemas import NorinthEvent, new_id
from .wrappers import first_present, record_model_call

_PATCHED: set[str] = set()

logger = logging.getLogger("norinth_logger")


def _error_summary(client, exc: BaseException) -> dict[str, Any]:
    """summarize an exception on the host's error path without adding one"""
    try:
        return summarize_error(exc, client.config.capture_content, client.config.fingerprint_key)
    except Exception:
        if not client.config.fail_open:
            raise
        return {"type": type(exc).__name__}


def _record_patched_call(
    client, *, provider, operation, prompt_getter, args, kwargs, response, status, error_summary, started
) -> None:
    """record a patched provider call; runs in the host's finally block, so it
    swallows its own failures when the client is fail-open"""
    try:
        record_model_call(
            client,
            provider=provider,
            operation=operation,
            prompt=prompt_getter(args, kwargs),
            kwargs=kwargs,
            response=response,
            status=status,
            error=error_summary,
            started=started,
        )
    except Exception:
        if not client.config.fail_open:
            raise
        logger.debug("Norinth failed to record a patched provider call; continuing", exc_info=True)


def autoinstrument(client) -> None:
    instrument_openai(client)
    instrument_anthropic(client)


def _openai_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    return first_present(kwargs, "input", "prompt")


def _messages(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    return kwargs.get("messages")


def instrument_openai(client) -> None:
    # Responses API (sync + async)
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
    # chat completions api (sync + async)
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
    # Messages API (sync + async)
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
            error = _error_summary(client, exc)
            raise
        finally:
            _record_patched_call(
                client,
                provider=provider,
                operation=operation,
                prompt_getter=prompt_getter,
                args=args,
                kwargs=kwargs,
                response=response,
                status=status,
                error_summary=error,
                started=started,
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
    """async counterpart; records the call only after the awaited coroutine resolves"""
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
            error = _error_summary(client, exc)
            raise
        finally:
            _record_patched_call(
                client,
                provider=provider,
                operation=operation,
                prompt_getter=prompt_getter,
                args=args,
                kwargs=kwargs,
                response=response,
                status=status,
                error_summary=error,
                started=started,
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

        # buffer only enough body to infer governance context, then replay it and
        # delegate the rest of receive() to the real transport. a forever-synthetic
        # receive() starves starlette's disconnect listener during a StreamingResponse
        # (worker spins at 100% cpu); delegating also bounds memory for large uploads
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

        # capture status so 4xx/5xx aren't recorded as success
        response_status = {"code": None}

        async def wrapped_send(event):
            if event.get("type") == "http.response.start":
                response_status["code"] = event.get("status")
            await send(event)

        workflow_name = workflow_name_from_path(scope.get("path", ""))
        try:
            metadata = infer_governance_context((decode_body(body),), {})
        except Exception:
            if not self.client.config.fail_open:
                raise
            metadata = {}
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
            error_summary = _error_summary(self.client, exc)
            raise
        finally:
            try:
                duration_ms = (perf_counter() - started) * 1000
                code = response_status["code"]
                if status != "error" and isinstance(code, int) and code >= 500:
                    status = "error"  # 5xx is a failed request
                config = self.client.config
                self.client.record(
                    NorinthEvent(
                        type="trace.completed",
                        trace_id=context.trace_id,
                        span_id=context.span_id,
                        service=config.service,
                        environment=config.environment,
                        project=config.project,
                        system=context.system,
                        name=workflow_name,
                        status=status,
                        duration_ms=duration_ms,
                        attributes={
                            # the inferred context came out of the request body,
                            # so it crosses the same content boundary as every
                            # other emitter's metadata: labels redacted and
                            # capped, anything else hashed
                            "metadata": sanitize_metadata(
                                context.metadata,
                                config.capture_content,
                                config.fingerprint_key,
                                getattr(config, "metadata_allowlist", None),
                            ),
                            "error": error_summary,
                            "http_status": code,
                        },
                    )
                )
            except Exception:
                if not self.client.config.fail_open:
                    raise
                logger.debug("Norinth failed to record a request trace; continuing", exc_info=True)
            finally:
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

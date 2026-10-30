# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from time import perf_counter
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import NorinthConfig
from .context import TraceContext, get_context, reset_context, set_context
from .privacy import (
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
from .schemas import NorinthEvent, new_id
from .spool import resolve_spool_dir, spool_off_reason
from .transport import EventTransport

logger = logging.getLogger("norinth_logger")

# an incident title is a label, not a narrative; cap it so a pasted record
# body cannot ride into the incident list under the title field
_MAX_TITLE_LEN = 200


def _fail_open(emit: Callable[..., None]) -> Callable[..., None]:
    """an emitter runs on the host's call path; with fail_open on, nothing it
    does (summarizing an odd object, inspecting a response) may raise into the
    host. the failure is logged at debug and the event is lost, as a dropped
    batch would be"""

    @wraps(emit)
    def guarded(self: NorinthClient, *args: Any, **kwargs: Any) -> None:
        try:
            emit(self, *args, **kwargs)
        except Exception:
            if not self.config.fail_open:
                raise
            logger.debug("Norinth could not build a %s event; continuing", emit.__name__, exc_info=True)

    return guarded


def _display_endpoint(endpoint: str) -> str:
    """the endpoint without any credentials embedded in its url"""
    parts = urlsplit(endpoint)
    if not parts.username and not parts.password:
        return endpoint
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


@dataclass
class _Span:
    name: str
    parent: TraceContext | None
    context: TraceContext
    token: Any
    started: float
    status: str = "success"
    error: dict[str, Any] | None = None

    def fail(self, exc: BaseException, config: NorinthConfig) -> None:
        self.status = "error"
        try:
            self.error = summarize_error(exc, config.capture_content, config.fingerprint_key)
        except Exception:
            if not config.fail_open:
                raise
            self.error = {"type": type(exc).__name__}


class NorinthClient:
    def __init__(self, config: NorinthConfig) -> None:
        spool_dir = resolve_spool_dir(config)
        if config.durable and not spool_dir:
            # strict mode: a deployment that treats these events as evidence
            # fails here, at boot, instead of at audit
            raise ValueError(
                f"durable delivery requires a spool and {spool_off_reason(config)}. Without a spool "
                "the transport drops events when delivery keeps failing, and the loss is only "
                "visible in the SDK's own counters"
            )
        self.config = config
        self.transport = EventTransport(config, spool_dir=spool_dir)
        if config.fingerprint_key_is_public:
            # the content boundary hashes with a key derived from the api key;
            # derived from the default key, every fingerprint is reversible by
            # anyone with a list of likely values, which is no privacy control
            logger.warning(
                "Norinth is hashing content with a key derived from the default api key, so fingerprints "
                "of short values can be reversed by guessing. Set NORINTH_API_KEY to the key your platform "
                "issued, or NORINTH_SIGNING_SECRET, before sending anything sensitive."
            )
        self.emit_sdk_health("initialized")

    def record(self, event: NorinthEvent) -> None:
        self._apply_identity_defaults(event)
        try:
            self.transport.enqueue(event.to_dict())
        except Exception:
            if not self.config.fail_open:
                raise

    def _apply_identity_defaults(self, event: NorinthEvent) -> None:
        """backfill configured app identity onto metadata; explicit event values win"""
        defaults = {
            key: value
            for key, value in (
                ("application_name", self.config.application_name),
                ("use_case", self.config.use_case),
            )
            if value
        }
        if not defaults:
            return
        metadata = event.attributes.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        for key, value in defaults.items():
            metadata.setdefault(key, value)
        event.attributes["metadata"] = metadata

    def _metadata(self, *sources: dict[str, Any] | None) -> dict[str, Any]:
        """merge context and caller metadata into a governance-safe mapping

        app metadata is arbitrary caller data, so it goes through the same
        content boundary as prompts and responses: with capture_content off,
        governance labels pass through redacted and anything else is hashed.
        see privacy.sanitize_metadata
        """
        merged: dict[str, Any] = {}
        for source in sources:
            if source:
                merged.update(source)
        return sanitize_metadata(
            merged,
            self.config.capture_content,
            self.config.fingerprint_key,
            self.config.metadata_allowlist,
        )

    @_fail_open
    def emit_sdk_health(self, state: str) -> None:
        stats = self.transport.stats
        self.record(
            NorinthEvent(
                type="sdk.health",
                trace_id=new_id("trc"),
                span_id=new_id("spn"),
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                name=state,
                status="success",
                attributes={
                    "mode": self.config.mode,
                    "fail_open": self.config.fail_open,
                    "async_transport": self.config.async_transport,
                    # report whether raw content capture is on
                    "capture_content": self.config.capture_content,
                    # report worker liveness and backlog so a stalled transport is visible
                    "thread_alive": self.transport.thread_alive(),
                    "queue_depth": stats.queued - stats.sent - stats.dropped,
                    "endpoint": _display_endpoint(self.config.endpoint),
                    "queued": stats.queued,
                    "sent": stats.sent,
                    "dropped": stats.dropped,
                    "failed_sends": stats.failed_sends,
                    "spooled": stats.spooled,
                    # report the durability posture so the platform can tell a
                    # service that may drop evidence from one that spools it
                    "durable": self.config.durable,
                    "spool_configured": bool(self.transport.spool_dir),
                },
            )
        )

    def trace(self, fn: Callable[..., Any] | None = None, *, system: str | None = None, name: str | None = None):
        """record a function as a trace span, for sync and async functions alike

        an async function is awaited inside the span, so the event carries the
        real duration and outcome and nested model calls join this trace
        """

        def decorator(inner: Callable[..., Any]):
            trace_name = name or inner.__name__
            function_ref = f"{inner.__module__}.{inner.__name__}"

            if inspect.iscoroutinefunction(inner):

                @wraps(inner)
                async def async_wrapped(*args: Any, **kwargs: Any):
                    span = self._open_span(trace_name, system, args, kwargs)
                    try:
                        return await inner(*args, **kwargs)
                    except Exception as exc:
                        span.fail(exc, self.config)
                        raise
                    finally:
                        self._close_span(span, function_ref, args, kwargs)

                return async_wrapped

            @wraps(inner)
            def wrapped(*args: Any, **kwargs: Any):
                span = self._open_span(trace_name, system, args, kwargs)
                try:
                    return inner(*args, **kwargs)
                except Exception as exc:
                    span.fail(exc, self.config)
                    raise
                finally:
                    self._close_span(span, function_ref, args, kwargs)

            return wrapped

        return decorator(fn) if fn else decorator

    def _open_span(self, trace_name: str, system: str | None, args: tuple[Any, ...], kwargs: dict[str, Any]) -> _Span:
        """start a span on the caller's thread; it must not raise into the host
        even when an argument refuses to be inspected"""
        parent = get_context()
        try:
            inferred = infer_governance_context(args, kwargs)
        except Exception:
            if not self.config.fail_open:
                raise
            logger.debug("Norinth could not infer governance context from the call; continuing", exc_info=True)
            inferred = {}
        context = TraceContext(
            trace_id=parent.trace_id if parent else new_id("trc"),
            span_id=new_id("spn"),
            system=system or (parent.system if parent else None),
            metadata={**(parent.metadata if parent else {}), **inferred, "workflow_name": trace_name},
        )
        return _Span(name=trace_name, parent=parent, context=context, token=set_context(context), started=perf_counter())

    def _close_span(self, span: _Span, function_ref: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        try:
            self.record(
                NorinthEvent(
                    type="trace.completed",
                    trace_id=span.context.trace_id,
                    span_id=span.context.span_id,
                    parent_span_id=span.parent.span_id if span.parent else None,
                    service=self.config.service,
                    environment=self.config.environment,
                    project=self.config.project,
                    system=span.context.system,
                    name=span.name,
                    status=span.status,
                    duration_ms=(perf_counter() - span.started) * 1000,
                    attributes={
                        "function": function_ref,
                        "call": summarize_call(args, kwargs, self.config.capture_content, self.config.fingerprint_key),
                        "metadata": self._metadata(span.context.metadata),
                        "error": span.error,
                    },
                ),
            )
        except Exception:
            if not self.config.fail_open:
                raise
            logger.debug("Norinth failed to record a trace span; continuing", exc_info=True)
        finally:
            reset_context(span.token)

    @_fail_open
    def model_call(
        self,
        *,
        provider: str,
        model: str,
        operation: str,
        prompt: Any | None = None,
        response: Any | None = None,
        usage: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        status: str = "success",
        duration_ms: float | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        self.record(
            NorinthEvent(
                type="model.call",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=operation,
                status=status,
                duration_ms=duration_ms,
                attributes={
                    "provider": provider,
                    "model": model,
                    "operation": operation,
                    "prompt": summarize_value(prompt, self.config.capture_content, self.config.fingerprint_key),
                    "response": summarize_value(response, self.config.capture_content, self.config.fingerprint_key),
                    "usage": sanitize_usage(usage, self.config.capture_content, self.config.fingerprint_key),
                    "metadata": self._metadata(context.metadata, metadata),
                    "error": sanitize_error_payload(error, self.config.capture_content, self.config.fingerprint_key),
                },
            ),
        )

    @_fail_open
    def retrieval(
        self,
        *,
        retriever: str,
        query: Any,
        documents: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
        status: str = "success",
        duration_ms: float | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        self.record(
            NorinthEvent(
                type="retrieval.call",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=retriever,
                status=status,
                duration_ms=duration_ms,
                attributes={
                    "retriever": retriever,
                    "query": summarize_value(query, self.config.capture_content, self.config.fingerprint_key),
                    "documents": summarize_value(documents, self.config.capture_content, self.config.fingerprint_key),
                    "document_count": len(documents),
                    "metadata": self._metadata(context.metadata, metadata),
                    "error": sanitize_error_payload(error, self.config.capture_content, self.config.fingerprint_key),
                },
            )
        )

    @_fail_open
    def tool_call(
        self,
        *,
        tool_name: str,
        arguments: Any | None = None,
        result: Any | None = None,
        metadata: dict[str, Any] | None = None,
        status: str = "success",
        duration_ms: float | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        self.record(
            NorinthEvent(
                type="tool.call",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=tool_name,
                status=status,
                duration_ms=duration_ms,
                attributes={
                    "tool_name": tool_name,
                    "arguments": summarize_value(arguments, self.config.capture_content, self.config.fingerprint_key),
                    "result": summarize_value(result, self.config.capture_content, self.config.fingerprint_key),
                    "metadata": self._metadata(context.metadata, metadata),
                    "error": sanitize_error_payload(error, self.config.capture_content, self.config.fingerprint_key),
                },
            )
        )

    @_fail_open
    def guardrail(
        self,
        *,
        guardrail_name: str,
        decision: str,
        score: float | None = None,
        matched_rules: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        status: str = "success",
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        self.record(
            NorinthEvent(
                type="guardrail.decision",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=guardrail_name,
                status=status,
                attributes={
                    "guardrail_name": guardrail_name,
                    "decision": decision,
                    "score": score,
                    # rule ids are labels; a guardrail library that surfaces the
                    # matched excerpt would otherwise carry content out verbatim
                    "matched_rules": sanitize_rule_labels(
                        matched_rules, self.config.capture_content, self.config.fingerprint_key
                    ),
                    "metadata": self._metadata(context.metadata, metadata),
                },
            )
        )

    @_fail_open
    def eval_result(
        self,
        *,
        eval_name: str,
        score: float,
        threshold: float,
        passed: bool,
        prompt_version: str | None = None,
        artifact_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        attributes: dict[str, Any] = {
            "eval_name": eval_name,
            "score": score,
            "threshold": threshold,
            "passed": passed,
            "metadata": self._metadata(context.metadata, metadata),
        }
        # the release gate only counts an eval as evidence if it names the build
        # it ran against (artifact_ref preferred, prompt_version fallback), and the
        # attestation signature covers these same fields; emit them so an eval
        # produced through this emitter can actually satisfy a gate
        if prompt_version is not None:
            attributes["prompt_version"] = prompt_version
        if artifact_ref is not None:
            attributes["artifact_ref"] = artifact_ref
        self.record(
            NorinthEvent(
                type="eval.result",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=eval_name,
                status="success" if passed else "error",
                attributes=attributes,
            )
        )

    @_fail_open
    def agent_run(
        self,
        *,
        agent_name: str,
        steps: list[dict[str, Any]],
        outcome: str,
        metadata: dict[str, Any] | None = None,
        status: str = "success",
        duration_ms: float | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        self.record(
            NorinthEvent(
                type="agent.run",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=agent_name,
                status=status,
                duration_ms=duration_ms,
                attributes={
                    "agent_name": agent_name,
                    # a step's tool/name labels feed the registry; its inputs,
                    # outputs and observations are content like any prompt
                    "steps": sanitize_steps(steps, self.config.capture_content, self.config.fingerprint_key),
                    "step_count": len(steps),
                    "outcome": outcome,
                    "metadata": self._metadata(context.metadata, metadata),
                },
            )
        )

    @_fail_open
    def prompt(
        self,
        *,
        prompt_id: str,
        version: str,
        application_name: str,
        workflow_name: str,
        artifact_ref: str,
        template: str,
        status: str,
        owner_ref: str | None = None,
        change_notes: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        event_metadata = self._metadata(
            context.metadata,
            metadata,
            {"application_name": application_name, "workflow_name": workflow_name},
        )
        self.record(
            NorinthEvent(
                type="prompt.event",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=prompt_id,
                status="success",
                attributes={
                    "prompt_id": prompt_id,
                    "version": version,
                    "artifact_ref": artifact_ref,
                    "prompt_status": status,
                    "owner_ref": owner_ref,
                    "template": summarize_value(template, self.config.capture_content, self.config.fingerprint_key),
                    "change_notes": summarize_value(change_notes, self.config.capture_content, self.config.fingerprint_key),
                    "metadata": event_metadata,
                },
            )
        )

    @_fail_open
    def deployment(
        self,
        *,
        deployment_id: str,
        version: str,
        application_name: str,
        workflow_name: str,
        artifact_ref: str,
        status: str,
        provider: str | None = None,
        model: str | None = None,
        prompt_version: str | None = None,
        deployed_by: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        event_metadata = self._metadata(
            context.metadata,
            metadata,
            {"application_name": application_name, "workflow_name": workflow_name},
        )
        self.record(
            NorinthEvent(
                type="deployment.event",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=deployment_id,
                status="success",
                attributes={
                    "deployment_id": deployment_id,
                    "version": version,
                    "artifact_ref": artifact_ref,
                    "deployment_status": status,
                    "provider": provider,
                    "model": model,
                    "prompt_version": prompt_version,
                    "deployed_by": deployed_by,
                    "metadata": event_metadata,
                },
            )
        )

    @_fail_open
    def incident(
        self,
        *,
        incident_id: str,
        title: str,
        severity: str,
        status: str,
        application_name: str,
        workflow_name: str,
        description: str,
        detected_by: str | None = None,
        impacted_trace_id: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        context = get_context() or TraceContext(trace_id=new_id("trc"), span_id=new_id("spn"))
        event_metadata = self._metadata(
            context.metadata,
            metadata,
            {"application_name": application_name, "workflow_name": workflow_name},
        )
        self.record(
            NorinthEvent(
                type="incident.event",
                trace_id=context.trace_id,
                span_id=new_id("spn"),
                parent_span_id=context.span_id,
                service=self.config.service,
                environment=self.config.environment,
                project=self.config.project,
                system=context.system,
                name=incident_id,
                status="error" if status in {"open", "investigating"} else "success",
                attributes={
                    "incident_id": incident_id,
                    # the title is the incident's label in every list and alert, so it
                    # stays readable rather than becoming a digest. it is an operator-
                    # authored short label, not narrative: redacted and length-capped,
                    # and documented as a field that must not carry phi
                    "title": redact_text(str(title))[:_MAX_TITLE_LEN],
                    "severity": severity,
                    "incident_status": status,
                    # an incident description is written by a person for the governance
                    # record, but it is still free text that can carry phi, so it obeys
                    # the content boundary like anything else. an org that wants the
                    # narrative in the record opts in with capture_incident_details,
                    # and redaction masks secret-shaped text either way. with capture
                    # off the reviewer gets a digest and reads the narrative in the
                    # incident system of record instead
                    "description": summarize_value(
                        description,
                        self.config.capture_content or self.config.capture_incident_details,
                        self.config.fingerprint_key,
                    ),
                    "detected_by": detected_by,
                    "impacted_trace_id": impacted_trace_id,
                    "provider": provider,
                    "model": model,
                    "metadata": event_metadata,
                },
            )
        )

    def shutdown(self) -> None:
        self.emit_sdk_health("shutdown")
        self.transport.shutdown()

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from time import perf_counter
from typing import Any

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
from .transport import EventTransport

# an incident title is a label, not a narrative; cap it so a pasted record
# body cannot ride into the incident list under the title field
_MAX_TITLE_LEN = 200


class NorinthClient:
    def __init__(self, config: NorinthConfig) -> None:
        if config.durable and not config.spool_dir:
            raise ValueError(
                "durable delivery requires spool_dir: without a disk spool the transport "
                "drops events when the queue fills or delivery keeps failing, and the loss "
                "is only visible in the SDK's own counters"
            )
        self.config = config
        self.transport = EventTransport(config)
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
                    "endpoint": self.config.endpoint,
                    "queued": stats.queued,
                    "sent": stats.sent,
                    "dropped": stats.dropped,
                    "failed_sends": stats.failed_sends,
                },
            )
        )

    def trace(self, fn: Callable[..., Any] | None = None, *, system: str | None = None, name: str | None = None):
        def decorator(inner: Callable[..., Any]):
            @wraps(inner)
            def wrapped(*args: Any, **kwargs: Any):
                parent = get_context()
                trace_name = name or inner.__name__
                inferred_metadata = {
                    **(parent.metadata if parent else {}),
                    **infer_governance_context(args, kwargs),
                    "workflow_name": trace_name,
                }
                context = TraceContext(
                    trace_id=parent.trace_id if parent else new_id("trc"),
                    span_id=new_id("spn"),
                    system=system or (parent.system if parent else None),
                    metadata=inferred_metadata,
                )
                token = set_context(context)
                started = perf_counter()
                status = "success"
                error_summary: dict[str, Any] | None = None
                try:
                    return inner(*args, **kwargs)
                except Exception as exc:
                    status = "error"
                    error_summary = summarize_error(exc, self.config.capture_content, self.config.fingerprint_key)
                    raise
                finally:
                    duration_ms = (perf_counter() - started) * 1000
                    try:
                        self.record(
                            NorinthEvent(
                                type="trace.completed",
                                trace_id=context.trace_id,
                                span_id=context.span_id,
                                parent_span_id=parent.span_id if parent else None,
                                service=self.config.service,
                                environment=self.config.environment,
                                project=self.config.project,
                                system=context.system,
                                name=name or inner.__name__,
                                status=status,
                                duration_ms=duration_ms,
                                attributes={
                                    "function": f"{inner.__module__}.{inner.__name__}",
                                    "call": summarize_call(args, kwargs, self.config.capture_content, self.config.fingerprint_key),
                                    "metadata": self._metadata(context.metadata),
                                    "error": error_summary,
                                },
                            ),
                        )
                    except Exception:
                        if not self.config.fail_open:
                            raise
                    finally:
                        reset_context(token)

            return wrapped

        return decorator(fn) if fn else decorator

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

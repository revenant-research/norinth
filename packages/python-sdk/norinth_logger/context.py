from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    system: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


_current_context: ContextVar[TraceContext | None] = ContextVar("norinth_context", default=None)


def get_context() -> TraceContext | None:
    return _current_context.get()


def set_context(context: TraceContext):
    return _current_context.set(context)


def reset_context(token: Token[TraceContext | None]) -> None:
    _current_context.reset(token)

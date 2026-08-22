from __future__ import annotations

from typing import Any, Callable

from .runtime import get_client


def trace(fn: Callable[..., Any] | None = None, *, system: str | None = None, name: str | None = None):
    return get_client().trace(fn, system=system, name=name)

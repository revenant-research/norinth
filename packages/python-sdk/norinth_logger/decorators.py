# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .runtime import get_client


def trace(fn: Callable[..., Any] | None = None, *, system: str | None = None, name: str | None = None):
    return get_client().trace(fn, system=system, name=name)

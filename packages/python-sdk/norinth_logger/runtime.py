# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from typing import Any

from .autoinstrument import NorinthFastAPIMiddleware
from .autoinstrument import autoinstrument as run_autoinstrument
from .client import NorinthClient
from .config import NorinthConfig
from .wrappers import wrap_client

_client: NorinthClient | None = None


def init(**kwargs: Any) -> NorinthClient:
    global _client
    _client = NorinthClient(NorinthConfig.from_env(**kwargs))
    return _client


def get_client() -> NorinthClient:
    global _client
    if _client is None:
        _client = NorinthClient(NorinthConfig.from_env())
    return _client


def shutdown() -> None:
    if _client is not None:
        _client.shutdown()


def wrap(client: Any):
    return wrap_client(client, get_client())


def autoinstrument() -> None:
    run_autoinstrument(get_client())


def instrument_fastapi(app: Any, *, system: str = "fastapi") -> None:
    app.add_middleware(NorinthFastAPIMiddleware, client=get_client(), system=system)


def retrieval(**kwargs: Any) -> None:
    get_client().retrieval(**kwargs)


def tool_call(**kwargs: Any) -> None:
    get_client().tool_call(**kwargs)


def guardrail(**kwargs: Any) -> None:
    get_client().guardrail(**kwargs)


def eval_result(**kwargs: Any) -> None:
    get_client().eval_result(**kwargs)


def agent_run(**kwargs: Any) -> None:
    get_client().agent_run(**kwargs)


def prompt(**kwargs: Any) -> None:
    get_client().prompt(**kwargs)


def deployment(**kwargs: Any) -> None:
    get_client().deployment(**kwargs)


def incident(**kwargs: Any) -> None:
    get_client().incident(**kwargs)

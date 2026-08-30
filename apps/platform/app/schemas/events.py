# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Event(BaseModel):
    type: str
    schema_version: str
    trace_id: str
    span_id: str
    timestamp: str
    service: str
    environment: str
    project: str
    parent_span_id: str | None = None
    system: str | None = None
    name: str | None = None
    status: str = "success"
    duration_ms: float | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


# cap one ingestion request so a hostile client can't pin the recompute path
# with an unbounded batch; larger senders split across requests
MAX_BATCH_EVENTS = 5000


class EventBatch(BaseModel):
    events: list[Event] = Field(..., max_length=MAX_BATCH_EVENTS)


class ScopeFilter(BaseModel):
    tenant_id: str | None = None
    project: str | None = None
    environment: str | None = None

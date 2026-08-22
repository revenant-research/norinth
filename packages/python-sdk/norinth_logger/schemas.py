from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = "2026-01"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


@dataclass
class NorinthEvent:
    type: str
    trace_id: str
    span_id: str
    service: str
    environment: str
    project: str
    timestamp: str = field(default_factory=utc_now)
    schema_version: str = SCHEMA_VERSION
    parent_span_id: str | None = None
    system: str | None = None
    name: str | None = None
    status: str = "success"
    duration_ms: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

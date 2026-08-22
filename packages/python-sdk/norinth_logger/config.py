from __future__ import annotations

from dataclasses import dataclass
from os import getenv


@dataclass(frozen=True)
class NorinthConfig:
    api_key: str
    signing_secret: str | None = None
    endpoint: str = "http://localhost:8001"
    project: str = "default"
    environment: str = "development"
    service: str = "unknown-service"
    # Optional governance identity for the host application. Setting these once
    # at init lets an existing app surface in the inventory without threading
    # governance fields through its own request models or business logic.
    application_name: str | None = None
    use_case: str | None = None
    mode: str = "observe"
    capture_content: bool = False
    async_transport: bool = True
    fail_open: bool = True
    max_queue_size: int = 1000
    flush_interval_seconds: float = 2.0
    timeout_seconds: float = 2.0

    @classmethod
    def from_env(cls, **overrides: object) -> "NorinthConfig":
        values = {
            "api_key": getenv("NORINTH_API_KEY", "dev"),
            "signing_secret": getenv("NORINTH_SIGNING_SECRET"),
            "endpoint": getenv("NORINTH_ENDPOINT", "http://localhost:8001"),
            "project": getenv("NORINTH_PROJECT", "default"),
            "environment": getenv("NORINTH_ENVIRONMENT", "development"),
            "service": getenv("NORINTH_SERVICE", "unknown-service"),
            "application_name": getenv("NORINTH_APPLICATION_NAME"),
            "use_case": getenv("NORINTH_USE_CASE"),
            "mode": getenv("NORINTH_MODE", "observe"),
            "capture_content": getenv("NORINTH_CAPTURE_CONTENT", "false").lower() == "true",
        }
        values.update({key: value for key, value in overrides.items() if value is not None})
        return cls(**values)

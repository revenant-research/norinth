"""metrics and structured logging, stdlib only

a prometheus client library would be a bigger liability than the hundred
lines below (house rule, same as services/totp.py): the exposition format is
plain text, a counter is a dict entry behind a lock, and nothing here runs on
the hot path more than once per request.

metrics: counters, histograms and scrape-time gauges rendered in prometheus
text format 0.0.4. label sets are kept small and bounded — route templates,
status classes, tenant ids — so cardinality cannot run away.

logging: NORINTH_LOG_JSON=1 switches the root logger to one json object per
line (timestamp, level, logger, message, request_id when a request is in
flight, plus any `extra` fields), which is what a log shipper wants. the
request id comes in on X-Request-ID or is generated, follows the request
through a contextvar, and returns on the response header.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

request_id_var: ContextVar[str | None] = ContextVar("norinth_request_id", default=None)

# fields every LogRecord carries; anything else on the record came in via
# `extra` and belongs in the json line
_STANDARD_LOG_FIELDS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime", "taskName"}


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        line: dict[str, Any] = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            line["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_FIELDS and not key.startswith("_"):
                try:
                    json.dumps(value)
                except (TypeError, ValueError):
                    value = str(value)
                line[key] = value
        if record.exc_info:
            line["exception"] = self.formatException(record.exc_info)
        return json.dumps(line, ensure_ascii=False)


def new_request_id(incoming: str | None) -> str:
    """propagate a sane caller-supplied id, otherwise mint one"""
    if incoming and len(incoming) <= 128 and incoming.replace("-", "").replace("_", "").isalnum():
        return incoming
    return uuid.uuid4().hex


# --- metrics registry -------------------------------------------------------------

_lock = threading.Lock()
_counters: dict[str, dict[str, Any]] = {}
_histograms: dict[str, dict[str, Any]] = {}
_gauges: dict[str, dict[str, Any]] = {}

# request latencies cluster in tens of milliseconds; the tail matters up to
# the point where a human gave up
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def _labels_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((labels or {}).items()))


def counter_inc(name: str, help_text: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
    with _lock:
        metric = _counters.setdefault(name, {"help": help_text, "series": {}})
        key = _labels_key(labels)
        metric["series"][key] = metric["series"].get(key, 0.0) + value


def histogram_observe(
    name: str,
    help_text: str,
    value: float,
    labels: dict[str, str] | None = None,
    buckets: tuple[float, ...] = DEFAULT_BUCKETS,
) -> None:
    with _lock:
        metric = _histograms.setdefault(name, {"help": help_text, "buckets": buckets, "series": {}})
        key = _labels_key(labels)
        series = metric["series"].setdefault(key, {"count": 0, "sum": 0.0, "bucket_counts": [0] * len(buckets)})
        series["count"] += 1
        series["sum"] += value
        for index, bound in enumerate(metric["buckets"]):
            if value <= bound:
                series["bucket_counts"][index] += 1


def gauge_callback(name: str, help_text: str, callback: Callable[[], float | dict[tuple[tuple[str, str], ...], float]]) -> None:
    """register a gauge evaluated at scrape time (e.g. a queue depth query)"""
    with _lock:
        _gauges[name] = {"help": help_text, "callback": callback}


def _escape_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_labels(key: tuple[tuple[str, str], ...], extra: str = "") -> str:
    parts = [f'{label}="{_escape_label(value)}"' for label, value in key]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


def render_metrics() -> str:
    """prometheus text exposition format 0.0.4"""
    lines: list[str] = []
    with _lock:
        for name in sorted(_counters):
            metric = _counters[name]
            lines.append(f"# HELP {name} {metric['help']}")
            lines.append(f"# TYPE {name} counter")
            for key, value in sorted(metric["series"].items()):
                lines.append(f"{name}{_render_labels(key)} {value}")
        for name in sorted(_histograms):
            metric = _histograms[name]
            lines.append(f"# HELP {name} {metric['help']}")
            lines.append(f"# TYPE {name} histogram")
            for key, series in sorted(metric["series"].items()):
                cumulative = 0
                for index, bound in enumerate(metric["buckets"]):
                    cumulative += series["bucket_counts"][index]
                    bucket_label = 'le="' + str(bound) + '"'
                    lines.append(f"{name}_bucket{_render_labels(key, bucket_label)} {cumulative}")
                inf_label = 'le="+Inf"'
                lines.append(f"{name}_bucket{_render_labels(key, inf_label)} {series['count']}")
                lines.append(f"{name}_sum{_render_labels(key)} {series['sum']}")
                lines.append(f"{name}_count{_render_labels(key)} {series['count']}")
        gauges = list(_gauges.items())
    # callbacks run outside the lock: a gauge that queries the database must
    # not serialize every other metric write behind it
    for name, metric in sorted(gauges):
        lines.append(f"# HELP {name} {metric['help']}")
        lines.append(f"# TYPE {name} gauge")
        try:
            value = metric["callback"]()
        except Exception:
            continue
        if isinstance(value, dict):
            for key, item in sorted(value.items()):
                lines.append(f"{name}{_render_labels(key)} {item}")
        else:
            lines.append(f"{name} {value}")
    return "\n".join(lines) + "\n"


def reset_metrics_for_tests() -> None:
    with _lock:
        _counters.clear()
        _histograms.clear()
        _gauges.clear()


class Timer:
    """context manager yielding elapsed seconds"""

    def __enter__(self) -> Timer:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.elapsed = time.perf_counter() - self._start

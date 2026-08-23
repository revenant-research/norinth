"""Regression tests for SDK transport resilience (audit C-8, F5/F6).

The overriding SDK contract is fail-open: a single bad event must never crash
or permanently kill the background worker, and the transport must not lie about
being healthy.
"""

from __future__ import annotations

import pathlib
import sys

SDK_DIR = pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"
sys.path.insert(0, str(SDK_DIR))


def _offline_transport():
    # Point at an unroutable endpoint so send always fails fast without a real
    # server; async_transport=False makes send synchronous for deterministic tests.
    from norinth_logger.config import NorinthConfig
    from norinth_logger.transport import EventTransport

    config = NorinthConfig(
        api_key="test",
        endpoint="http://127.0.0.1:9",  # discard port; connection refused
        async_transport=False,
        timeout_seconds=0.2,
        max_send_retries=0,  # keep offline tests fast; retry paths tested separately
        retry_backoff_seconds=0,
    )
    return EventTransport(config)


class _Unserializable:
    """repr is fine but the object is not JSON-serializable."""


def test_non_serializable_event_is_dropped_not_fatal():
    transport = _offline_transport()
    # A non-JSON-native value used to crash json.dumps in the worker path.
    transport.send_batch([{"bad": _Unserializable(), "nested": {"x": float("nan")}}])
    # It is counted as dropped, and no exception escaped.
    assert transport.stats.dropped >= 1


def test_nan_score_does_not_poison_the_batch():
    transport = _offline_transport()
    # allow_nan=False => NaN can't silently produce invalid JSON; the batch is
    # dropped defensively rather than sent as a poison payload.
    transport.send_batch([{"guardrail": "x", "score": float("nan")}])
    assert transport.stats.dropped >= 1


def test_worker_survives_and_restarts_after_death():
    from norinth_logger.config import NorinthConfig
    from norinth_logger.transport import EventTransport

    config = NorinthConfig(api_key="t", endpoint="http://127.0.0.1:9", async_transport=True, timeout_seconds=0.2, max_send_retries=0, retry_backoff_seconds=0)
    transport = EventTransport(config)
    assert transport.thread_alive()

    # Simulate a dead worker; the next enqueue must resurrect it.
    transport._stop.clear()
    transport._worker = None
    transport.enqueue({"type": "model.call"})
    assert transport.thread_alive()
    transport.shutdown()


def test_send_failure_is_counted_not_raised():
    transport = _offline_transport()
    transport.send_batch([{"type": "model.call"}])
    assert transport.stats.failed_sends >= 1

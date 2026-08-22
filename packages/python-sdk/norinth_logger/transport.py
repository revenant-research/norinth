from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass
from urllib import request
from urllib.error import URLError

from .config import NorinthConfig

logger = logging.getLogger("norinth_logger")
# A library must not configure the root logger. Adding a NullHandler prevents
# "No handlers could be found" warnings and stops the SDK from spamming stderr in
# a host app that has not configured logging (audit F5).
logger.addHandler(logging.NullHandler())


def sign_payload(payload: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    return mac.hexdigest()


@dataclass
class TransportStats:
    queued: int = 0
    sent: int = 0
    dropped: int = 0
    failed_sends: int = 0


class EventTransport:
    """Fail-open, background-batching transport.

    The overriding contract (audit C-8): nothing here may crash, block, or kill
    the host application, and the background worker must never die silently. A
    single bad event must not stop telemetry: serialization is defensive, the
    worker loop is fully guarded, and a dead worker is restarted on the next
    enqueue.
    """

    def __init__(self, config: NorinthConfig) -> None:
        self.config = config
        self.stats = TransportStats()
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=config.max_queue_size)
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()
        if config.async_transport:
            self._start_worker()
            atexit.register(self._atexit_flush)
            self._register_fork_handler()

    # -- worker lifecycle ---------------------------------------------------

    def _start_worker(self) -> None:
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="norinth-transport", daemon=True)
        self._worker.start()

    def _ensure_worker(self) -> None:
        """Restart the worker if it has died (e.g. after a fork, or if an
        unexpected error ever escaped the guarded loop)."""
        if not self.config.async_transport or self._stop.is_set():
            return
        if self._worker is not None and self._worker.is_alive():
            return
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._start_worker()

    def thread_alive(self) -> bool:
        return bool(self._worker and self._worker.is_alive())

    def _register_fork_handler(self) -> None:
        # Under prefork servers (gunicorn, celery) the child inherits a queue
        # with no consumer thread. Reset and restart the worker in the child so
        # telemetry keeps flowing (audit F2).
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    def _after_fork(self) -> None:
        self._queue = queue.Queue(maxsize=self.config.max_queue_size)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._worker = None
        if self.config.async_transport:
            self._start_worker()

    # -- enqueue / flush ----------------------------------------------------

    def enqueue(self, event: dict) -> None:
        try:
            if self.config.async_transport:
                self._ensure_worker()
                self._queue.put_nowait(event)
                self.stats.queued += 1
            else:
                self.send_batch([event])
        except queue.Full:
            self.stats.dropped += 1
            logger.warning("Norinth event queue full; dropping event")
        except Exception:
            self.stats.dropped += 1
            logger.debug("Norinth failed to enqueue event", exc_info=True)

    def flush(self) -> None:
        batch: list[dict] = []
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self.send_batch(batch)

    def shutdown(self) -> None:
        self._stop.set()
        self.flush()
        worker = self._worker
        if worker and worker.is_alive():
            worker.join(timeout=self.config.timeout_seconds)

    def _atexit_flush(self) -> None:
        try:
            self.flush()
        except Exception:
            # Never raise during interpreter shutdown.
            pass

    def _run(self) -> None:
        # The entire loop body is guarded so no exception (serialization,
        # network, or otherwise) can ever terminate the worker thread.
        while not self._stop.is_set():
            try:
                time.sleep(self.config.flush_interval_seconds)
                self.flush()
            except Exception:
                logger.debug("Norinth transport worker error; continuing", exc_info=True)

    # -- send ---------------------------------------------------------------

    def send_batch(self, events: list[dict]) -> None:
        try:
            # default=str tolerates non-JSON-native values; allow_nan=False turns
            # NaN/Infinity (which are invalid JSON the receiver would reject) into
            # a caught error instead of a poisoned batch. Serialization happens
            # inside the guard so a bad event is dropped, not fatal (audit C-8/F6).
            payload = json.dumps(
                {"events": events},
                separators=(",", ":"),
                default=str,
                allow_nan=False,
            ).encode("utf-8")
        except Exception:
            self.stats.dropped += len(events)
            logger.debug("Norinth failed to serialize event batch; dropping", exc_info=True)
            return

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        if self.config.signing_secret:
            headers["X-Norinth-Signature"] = f"sha256={sign_payload(payload, self.config.signing_secret)}"

        http_request = request.Request(
            f"{self.config.endpoint.rstrip('/')}/v1/events/batch",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
                if response.status >= 400:
                    raise URLError(f"Norinth ingestion failed with status {response.status}")
            self.stats.sent += len(events)
        except Exception:
            self.stats.failed_sends += 1
            logger.debug("Norinth failed to send event batch", exc_info=True)

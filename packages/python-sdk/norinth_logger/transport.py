# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import atexit
import glob
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass
from urllib import request
from urllib.error import HTTPError

from .config import NorinthConfig

# statuses worth retrying: server overloaded or timed out, not malformed. other
# 4xx will be rejected again no matter what, so not retried/spooled
_RETRIABLE_STATUS = {408, 429, 500, 502, 503, 504}

logger = logging.getLogger("norinth_logger")
# a library must not configure the root logger; nullhandler avoids "no handlers"
# warnings and stops spamming stderr in a host app without logging configured
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
    retried: int = 0
    spooled: int = 0


class EventTransport:
    """fail-open background-batching transport; never crash/block the host, and the worker must not die silently"""

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
        """restart the worker if it died (fork, or an escaped error)"""
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
        # prefork servers (gunicorn, celery): child inherits a queue with no
        # consumer thread, so reset and restart the worker in the child
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
        # drain disk spool first so spooled events go out ahead of the queue
        self._drain_spool()
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
            # never raise during interpreter shutdown
            pass

    def _run(self) -> None:
        # loop body fully guarded so no exception can kill the worker thread
        while not self._stop.is_set():
            try:
                time.sleep(self.config.flush_interval_seconds)
                self.flush()
            except Exception:
                logger.debug("Norinth transport worker error; continuing", exc_info=True)

    # -- send ---------------------------------------------------------------

    def send_batch(self, events: list[dict]) -> None:
        try:
            # default=str tolerates non-json values; allow_nan=False makes NaN/Inf
            # (invalid json the receiver rejects) raise here so one bad event is
            # dropped, not fatal
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
        self._deliver(payload, len(events))

    def _post_once(self, payload: bytes) -> None:
        """send one payload; raises on any transport or http failure"""
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
        with request.urlopen(http_request, timeout=self.config.timeout_seconds) as response:
            if response.status >= 400:
                raise HTTPError(http_request.full_url, response.status, "ingestion failed", response.headers, None)

    @staticmethod
    def _is_retriable(exc: Exception) -> bool:
        if isinstance(exc, HTTPError):
            return exc.code in _RETRIABLE_STATUS
        # timeouts and connection errors are transient
        return True

    def _deliver(self, payload: bytes, count: int) -> None:
        """deliver a batch with bounded retry, then spool or drop; permanent 4xx dropped immediately"""
        for attempt in range(self.config.max_send_retries + 1):
            try:
                self._post_once(payload)
                self.stats.sent += count
                return
            except Exception as exc:  # noqa: BLE001 - transport must never raise into the host
                self.stats.failed_sends += 1
                if not self._is_retriable(exc):
                    self.stats.dropped += count
                    logger.warning(
                        "Norinth ingestion rejected the batch permanently; dropping %d event(s): %s",
                        count,
                        exc,
                    )
                    return
                if attempt < self.config.max_send_retries:
                    self.stats.retried += 1
                    time.sleep(self.config.retry_backoff_seconds * (2**attempt))
                    continue
                logger.debug("Norinth failed to send event batch after retries", exc_info=True)

        if self._spool(payload, count):
            return
        self.stats.dropped += count
        logger.warning("Norinth dropped %d event(s): delivery failed and no spool configured", count)

    # -- spool --------------------------------------------------------------

    def _spool(self, payload: bytes, count: int) -> bool:
        spool_dir = self.config.spool_dir
        if not spool_dir:
            return False
        try:
            os.makedirs(spool_dir, exist_ok=True)
            if self._spool_size(spool_dir) + len(payload) > self.config.spool_max_bytes:
                logger.warning("Norinth spool is full; dropping %d event(s)", count)
                return False
            path = os.path.join(spool_dir, f"{int(time.time() * 1000)}-{uuid.uuid4().hex}.json")
            tmp = f"{path}.tmp"
            with open(tmp, "wb") as handle:
                handle.write(payload)
            os.replace(tmp, path)
            self.stats.spooled += count
            return True
        except Exception:
            logger.debug("Norinth failed to spool event batch", exc_info=True)
            return False

    @staticmethod
    def _spool_size(spool_dir: str) -> int:
        total = 0
        for path in glob.glob(os.path.join(spool_dir, "*.json")):
            try:
                total += os.path.getsize(path)
            except OSError:
                continue
        return total

    def _drain_spool(self) -> None:
        spool_dir = self.config.spool_dir
        if not spool_dir or not os.path.isdir(spool_dir):
            return
        for path in sorted(glob.glob(os.path.join(spool_dir, "*.json"))):
            try:
                with open(path, "rb") as handle:
                    payload = handle.read()
            except OSError:
                continue
            try:
                self._post_once(payload)
            except Exception:
                # still failing; leave on disk for a later flush
                return
            self.stats.sent += self._event_count(payload)
            try:
                os.remove(path)
            except OSError:
                pass

    @staticmethod
    def _event_count(payload: bytes) -> int:
        try:
            return len(json.loads(payload).get("events", []))
        except Exception:
            return 0

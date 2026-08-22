from __future__ import annotations

import hmac
import hashlib
import json
import logging
import queue
import threading
import time
from dataclasses import dataclass
from urllib import request
from urllib.error import URLError

from .config import NorinthConfig

logger = logging.getLogger("norinth_logger")

def sign_payload(payload: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=payload, digestmod=hashlib.sha256)
    return mac.hexdigest()


@dataclass
class TransportStats:
    queued: int = 0
    sent: int = 0
    dropped: int = 0
    failed_sends: int = 0


class EventTransport:
    def __init__(self, config: NorinthConfig) -> None:
        self.config = config
        self.stats = TransportStats()
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=config.max_queue_size)
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        if config.async_transport:
            self._worker = threading.Thread(target=self._run, name="norinth-transport", daemon=True)
            self._worker.start()

    def enqueue(self, event: dict) -> None:
        try:
            if self.config.async_transport:
                self._queue.put_nowait(event)
                self.stats.queued += 1
            else:
                self.send_batch([event])
        except queue.Full:
            self.stats.dropped += 1
            logger.warning("Norinth event queue full; dropping event")
        except Exception:
            self.stats.dropped += 1
            logger.exception("Norinth failed to enqueue event")

    def flush(self) -> None:
        batch: list[dict] = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self.send_batch(batch)

    def shutdown(self) -> None:
        self._stop.set()
        self.flush()

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.config.flush_interval_seconds)
            self.flush()

    def send_batch(self, events: list[dict]) -> None:
        payload = json.dumps({"events": events}, separators=(',', ':')).encode("utf-8")
        
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

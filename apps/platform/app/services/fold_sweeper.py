# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""background fold recovery

the request path folds each batch into derived state and a fold failure re-raises
so the client's retry re-folds. two failure modes escape that: a client that gets
a 500 and never retries, and a process killed mid-fold. both leave raw events
stored but pending (folded_at NULL). this worker folds anything left pending, so
derived state — the audit evidence — always catches up to the raw record.

it complements, and never replaces, the request-path fold: on a healthy install
it finds nothing to do. the interval is short because a pending row is missing
evidence, which for a governance platform is the failure that matters most.

env config:
  NORINTH_FOLD_SWEEPER=0 disables the worker thread (tests)
  NORINTH_FOLD_SWEEPER_INTERVAL_SECONDS -- seconds between passes (30)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from app.storage import db
from app.storage.fold import sweep_tenant
from app.storage.raw_events import connect, tenants_with_unfolded

log = logging.getLogger(__name__)

# transaction-scoped try-lock so only one replica sweeps at a time; the fold is
# idempotent across replicas (counted_at keeps the increment exactly-once), but a
# single sweeper avoids two replicas doing the same recovery work. sqlite is
# effectively single-writer, so this is a no-op there
_FOLD_SWEEP_LOCK_KEY = 4242000042420004

DEFAULT_INTERVAL_SECONDS = 30.0


def _interval_seconds() -> float:
    raw = os.getenv("NORINTH_FOLD_SWEEPER_INTERVAL_SECONDS")
    if not raw:
        return DEFAULT_INTERVAL_SECONDS
    try:
        value = float(raw)
    except ValueError:
        log.warning("NORINTH_FOLD_SWEEPER_INTERVAL_SECONDS is not a number: %r", raw)
        return DEFAULT_INTERVAL_SECONDS
    return value if value > 0 else DEFAULT_INTERVAL_SECONDS


def run_once() -> dict[str, Any]:
    """fold every tenant's pending rows; skipped when another replica holds the lock"""
    if db.is_postgres():
        lock_conn = connect()
        try:
            held = lock_conn.execute(
                f"SELECT pg_try_advisory_lock({_FOLD_SWEEP_LOCK_KEY}) AS held"
            ).fetchone()["held"]
            if not held:
                return {"skipped": True, "folded": 0}
            try:
                return _pass()
            finally:
                lock_conn.execute(f"SELECT pg_advisory_unlock({_FOLD_SWEEP_LOCK_KEY})")
        finally:
            lock_conn.close()
    return _pass()


def _pass() -> dict[str, Any]:
    folded = 0
    failed = 0
    for tenant_id in tenants_with_unfolded():
        try:
            result = sweep_tenant(tenant_id)
        except Exception:  # noqa: BLE001 - one tenant must not stop the rest
            log.exception("fold sweep failed for tenant %s", tenant_id)
            continue
        folded += result["folded"]
        failed += result["failed"]
    return {"skipped": False, "folded": folded, "failed": failed}


_worker_started = False


def start_worker(interval_seconds: float | None = None) -> None:
    """background fold-recovery loop, idempotent; disabled with NORINTH_FOLD_SWEEPER=0"""
    global _worker_started
    if _worker_started or os.getenv("NORINTH_FOLD_SWEEPER", "1").lower() in {"0", "false", "no"}:
        return
    _worker_started = True
    interval = interval_seconds if interval_seconds is not None else _interval_seconds()

    def loop() -> None:
        while True:
            try:
                run_once()
            except Exception:  # noqa: BLE001 - a failed pass must not kill the loop
                log.exception("fold sweep pass failed")
            time.sleep(interval)

    threading.Thread(target=loop, name="norinth-fold-sweeper", daemon=True).start()

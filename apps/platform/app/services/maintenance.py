"""periodic governance maintenance

governance state that turns on the clock rather than on an event -- an exception
reaching its expiry date, a review task passing its due or escalation date --
used to be recomputed only while a batch of telemetry was being ingested. an
application that had gone quiet therefore stopped ageing: a lapsed risk
acceptance kept counting as remediation and an overdue review was never raised
or escalated. this runs those transitions on a timer instead

env config:
  NORINTH_MAINTENANCE_WORKER=0 disables the worker thread (tests)
  NORINTH_MAINTENANCE_INTERVAL_SECONDS -- seconds between passes (300)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from app.storage import db
from app.storage.audit import record_audit
from app.storage.raw_events import connect
from app.storage.retention import purge_events_older_than, tenants_with_retention_window
from app.storage.workflow import expire_due_exceptions, refresh_workflow_state

log = logging.getLogger(__name__)

# transaction-scoped try-lock so only one replica runs a pass; the transitions
# are idempotent, but two replicas racing would emit duplicate overdue and
# escalation notifications. sqlite is effectively single-writer, so it's a no-op
_MAINTENANCE_LOCK_KEY = 4242000042420003

DEFAULT_INTERVAL_SECONDS = 300.0


def _interval_seconds() -> float:
    raw = os.getenv("NORINTH_MAINTENANCE_INTERVAL_SECONDS")
    if not raw:
        return DEFAULT_INTERVAL_SECONDS
    try:
        value = float(raw)
    except ValueError:
        log.warning("NORINTH_MAINTENANCE_INTERVAL_SECONDS is not a number: %r", raw)
        return DEFAULT_INTERVAL_SECONDS
    return value if value > 0 else DEFAULT_INTERVAL_SECONDS


def run_once() -> dict[str, Any]:
    """advance clock-driven governance state

    returns what it did, or skipped=True when another replica holds the lock
    """
    if db.is_postgres():
        lock_conn = connect()
        try:
            held = lock_conn.execute(f"SELECT pg_try_advisory_lock({_MAINTENANCE_LOCK_KEY}) AS held").fetchone()["held"]
            if not held:
                return {"skipped": True, "expired_exceptions": 0}
            try:
                return _pass()
            finally:
                lock_conn.execute(f"SELECT pg_advisory_unlock({_MAINTENANCE_LOCK_KEY})")
        finally:
            lock_conn.close()
    return _pass()


def _pass() -> dict[str, Any]:
    expired = expire_due_exceptions()
    # recomputes review queue due/overdue/escalated state, which also raises the
    # overdue and escalation notifications
    refresh_workflow_state()
    return {"skipped": False, "expired_exceptions": expired, "purged_events": _enforce_retention()}


def _enforce_retention() -> dict[str, int]:
    """age out telemetry for organizations that configured a retention window

    only organizations that set one are touched; the deletion is irreversible so
    it is recorded in the audit log, which is itself never purged
    """
    purged: dict[str, int] = {}
    for policy in tenants_with_retention_window():
        tenant_id = policy["tenant_id"]
        try:
            deleted = purge_events_older_than(policy["retention_days"], tenant_id=tenant_id)
        except Exception:  # noqa: BLE001 - one organization must not stop the rest
            log.exception("retention purge failed for tenant %s", tenant_id)
            continue
        if deleted:
            purged[tenant_id] = deleted
            record_audit(
                actor_ref="system:retention",
                action="retention.purge_events",
                tenant_id=tenant_id,
                target_type="retention",
                target_id=str(policy["retention_days"]),
                detail={"deleted_events": deleted, "retention_days": policy["retention_days"]},
            )
    return purged


_worker_started = False


def start_worker(interval_seconds: float | None = None) -> None:
    """background maintenance loop, idempotent; disabled with NORINTH_MAINTENANCE_WORKER=0"""
    global _worker_started
    if _worker_started or os.getenv("NORINTH_MAINTENANCE_WORKER", "1").lower() in {"0", "false", "no"}:
        return
    _worker_started = True
    interval = interval_seconds if interval_seconds is not None else _interval_seconds()

    def loop() -> None:
        while True:
            try:
                run_once()
            except Exception:  # noqa: BLE001 - a failed pass must not kill the loop
                log.exception("governance maintenance pass failed")
            time.sleep(interval)

    threading.Thread(target=loop, name="norinth-maintenance", daemon=True).start()

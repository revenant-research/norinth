# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""fold pending raw events into derived state, recoverably

insert_events commits the raw event; the fold projects it into the inventory,
fingerprints, assessments, posture, workflow state and release gates. those
projections each open their own connection and commit independently, so there is
no single transaction over the sequence. the durable fold ledger on sdk_events
(folded_at / counted_at, see migration _0023_fold_ledger) makes a failure in the
middle recoverable instead of silently lost:

  * the request path folds everything still pending for the tenant — this batch,
    plus anything an earlier batch stored but failed to fold. a fold failure
    re-raises (the client sees it, and a retry re-folds), and the rows stay
    pending until a fold completes.
  * the one non-idempotent projection (process_events, which increments) is made
    exactly-once by counted_at, so re-folding never double counts.
  * a background sweeper (services/fold_sweeper) is the backstop for a client
    that never retries and for a process killed mid-fold. it folds row-by-row
    when a whole-set fold fails, so one poison row cannot block the rest.

env config:
  NORINTH_FOLD_CLAIM_LIMIT   rows folded per pass (default 10000, above the max
                             batch size so a normal batch always folds in full)
  NORINTH_FOLD_MAX_ATTEMPTS  fold failures after which the request path skips a
                             row (quarantine) so live ingest is never wedged (5)
"""

from __future__ import annotations

import logging
import os
from typing import Any

from app.services.observability import counter_inc
from app.storage.agents import refresh_agent_posture
from app.storage.deployments import process_deployment_events, refresh_deployment_gates
from app.storage.entities import process_events
from app.storage.governance_policy import fold_batch_assessments
from app.storage.incidents import process_incident_events
from app.storage.lifecycle import fold_batch_fingerprints
from app.storage.policy_engine import refresh_vendor_posture
from app.storage.prompts import process_prompt_events
from app.storage.raw_events import claim_unfolded, mark_folded, record_fold_attempt
from app.storage.workflow import expire_due_exceptions, refresh_workflow_state

log = logging.getLogger(__name__)

DEFAULT_CLAIM_LIMIT = 10000
DEFAULT_MAX_ATTEMPTS = 5


def claim_limit() -> int:
    try:
        value = int(os.getenv("NORINTH_FOLD_CLAIM_LIMIT", str(DEFAULT_CLAIM_LIMIT)))
    except ValueError:
        return DEFAULT_CLAIM_LIMIT
    return value if value > 0 else DEFAULT_CLAIM_LIMIT


def max_attempts() -> int:
    try:
        value = int(os.getenv("NORINTH_FOLD_MAX_ATTEMPTS", str(DEFAULT_MAX_ATTEMPTS)))
    except ValueError:
        return DEFAULT_MAX_ATTEMPTS
    return value if value > 0 else DEFAULT_MAX_ATTEMPTS


def batch_scopes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """scopes a batch touches; derived state recomputes only for these"""
    seen: dict[tuple, dict[str, Any]] = {}
    for event in events:
        metadata = (event.get("attributes") or {}).get("metadata") or {}
        application_name = metadata.get("application_name")
        if not application_name:
            continue
        scope = {
            "tenant_id": metadata.get("tenant_id"),
            "project": event.get("project"),
            "environment": event.get("environment"),
            "application_name": application_name,
        }
        seen[tuple(scope.values())] = scope
    return list(seen.values())


def _fold_rows(tenant_id: str, pending: list[dict[str, Any]]) -> None:
    """run every projection over a claimed set of pending rows

    process_events counts exactly once (via counted_at) and must run first so the
    application/workflow inventory exists before fingerprints and the refresh
    steps read it. every other step is idempotent — a natural-key upsert, a
    monotone set union, or a scope recompute — so re-running this after a later
    step failed reproduces the same derived state without double counting.
    """
    events = [row["event"] for row in pending]
    process_events(pending)
    process_prompt_events(events)
    process_deployment_events(events)
    process_incident_events(events)
    expire_due_exceptions()
    scopes = batch_scopes(events)
    fold_batch_fingerprints(events)
    fold_batch_assessments(events)
    refresh_agent_posture([tenant_id])
    refresh_vendor_posture([tenant_id])
    refresh_workflow_state(scopes)
    refresh_deployment_gates(scopes)


def fold_pending(tenant_id: str, *, include_quarantined: bool = False, limit: int | None = None) -> dict[str, Any]:
    """fold the pending rows for a tenant as one set; re-raise on failure

    the request path calls this. a failure re-raises so the client learns the
    batch was not fully projected (a retry re-folds), and record_fold_attempt has
    already counted the failure so a row that keeps failing is quarantined and,
    once past the budget, skipped here to keep live ingest moving.
    """
    pending = claim_unfolded(
        tenant_id,
        limit=limit if limit is not None else claim_limit(),
        max_attempts=None if include_quarantined else max_attempts(),
    )
    if not pending:
        return {"folded": 0}
    ids = [row["id"] for row in pending]
    try:
        _fold_rows(tenant_id, pending)
    except Exception as error:
        record_fold_attempt(ids, repr(error))
        counter_inc(
            "norinth_fold_failures_total",
            "Ingest fold passes that raised, by tenant",
            {"tenant": tenant_id or "unknown"},
        )
        log.warning("fold failed for tenant %s over %d pending rows", tenant_id, len(ids), exc_info=True)
        raise
    mark_folded(ids)
    return {"folded": len(ids)}


def sweep_tenant(tenant_id: str) -> dict[str, int]:
    """fold a tenant's pending rows for the background sweeper, isolating poison

    includes quarantined rows so a deployed fix lets them recover. tries the set
    as a whole first (the fast, common case is a whole-batch transient failure
    that now succeeds); if that fails, folds each row alone so a single row that
    cannot fold does not hold up every row queued behind it.
    """
    pending = claim_unfolded(tenant_id, limit=claim_limit(), max_attempts=None)
    if not pending:
        return {"folded": 0, "failed": 0}
    ids = [row["id"] for row in pending]
    try:
        _fold_rows(tenant_id, pending)
    except Exception:
        log.warning("whole-set fold failed for tenant %s; isolating %d rows", tenant_id, len(ids), exc_info=True)
    else:
        mark_folded(ids)
        _count_recovered(tenant_id, len(ids))
        return {"folded": len(ids), "failed": 0}

    folded = 0
    failed = 0
    for row in pending:
        try:
            _fold_rows(tenant_id, [row])
        except Exception as error:
            record_fold_attempt([row["id"]], repr(error))
            failed += 1
        else:
            mark_folded([row["id"]])
            folded += 1
    if failed:
        counter_inc(
            "norinth_fold_failures_total",
            "Ingest fold passes that raised, by tenant",
            {"tenant": tenant_id or "unknown"},
        )
        log.error("fold sweep left %d unfoldable rows for tenant %s", failed, tenant_id)
    _count_recovered(tenant_id, folded)
    return {"folded": folded, "failed": failed}


def _count_recovered(tenant_id: str, folded: int) -> None:
    """rows the sweeper folded are rows the request path did not complete — a
    recovery, counted so the backstop's activity is visible"""
    if folded:
        counter_inc(
            "norinth_fold_recovered_total",
            "Pending rows folded by the background sweeper, by tenant",
            {"tenant": tenant_id or "unknown"},
            folded,
        )

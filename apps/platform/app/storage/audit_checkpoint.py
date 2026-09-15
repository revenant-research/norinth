# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Signed audit heads on storage separate from the database.

NORINTH_AUDIT_CHECKPOINT_PATH should name a retained, append-only file on a
separate volume. A database writer cannot edit this journal. Its HMAC chain
detects changes to individual checkpoints; rollback resistance additionally
requires the operator to retain the journal on versioned or immutable storage.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def checkpoint_path() -> Path | None:
    value = os.getenv("NORINTH_AUDIT_CHECKPOINT_PATH")
    return Path(value) if value else None


@contextmanager
def checkpoint_lock() -> Iterator[None]:
    path = checkpoint_path()
    if path is None:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path) + ".lock", "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _payload(entry: dict[str, Any]) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_checkpoints(keyring: dict[str, bytes]) -> tuple[list[dict[str, Any]], str | None]:
    path = checkpoint_path()
    if path is None or not path.exists():
        return [], "unavailable"
    if not keyring:
        return [], "verification_key_unavailable"
    records: list[dict[str, Any]] = []
    previous_seal = "0" * 64
    try:
        with path.open("r", encoding="utf-8") as journal:
            for line in journal:
                record = json.loads(line)
                seal = record.pop("seal")
                key = keyring.get(record["key_id"])
                if key is None or record["previous_seal"] != previous_seal:
                    return [], "checkpoint_chain"
                expected = hmac.new(key, _payload(record), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(seal, expected):
                    return [], "checkpoint_hmac"
                if records:
                    previous = records[-1]
                    if record.get("kind") == "reconcile":
                        if record["epoch"] == previous["epoch"] or record.get("previous_epoch") != previous["epoch"]:
                            return [], "checkpoint_order"
                    elif record["epoch"] != previous["epoch"] or record["count"] <= previous["count"]:
                        return [], "checkpoint_order"
                record["seal"] = seal
                records.append(record)
                previous_seal = seal
    except (OSError, ValueError, KeyError, TypeError):
        return [], "checkpoint_unreadable"
    return (records, None) if records else ([], "unavailable")


def latest_checkpoint(keyring: dict[str, bytes]) -> dict[str, Any] | None:
    """Read only the latest record on append; full verification scans history."""
    path = checkpoint_path()
    if path is None or not path.exists() or path.stat().st_size == 0:
        return None
    with path.open("rb") as journal:
        journal.seek(0, os.SEEK_END)
        end = journal.tell()
        if end == 0:
            return None
        journal.seek(end - 1)
        if journal.read(1) != b"\n":
            raise RuntimeError("Audit checkpoint journal ends with an incomplete record")
        position = end - 2
        while position >= 0:
            journal.seek(position)
            if journal.read(1) == b"\n":
                break
            position -= 1
        journal.seek(position + 1)
        record = json.loads(journal.read(end - position - 2))
    seal = record.pop("seal")
    key = keyring.get(record["key_id"])
    if key is None or not hmac.compare_digest(seal, hmac.new(key, _payload(record), hashlib.sha256).hexdigest()):
        raise RuntimeError("Latest audit checkpoint cannot be authenticated")
    record["seal"] = seal
    return record


def append_checkpoint(count: int, head_hash: str, key_id: str, key: bytes, keyring: dict[str, bytes]) -> None:
    path = checkpoint_path()
    if path is None:
        return
    previous = latest_checkpoint(keyring)
    if previous and count <= previous["count"]:
        raise RuntimeError("Audit checkpoint count did not advance")
    entry = {
        "kind": "head",
        "epoch": previous["epoch"] if previous else uuid.uuid4().hex,
        "count": count,
        "head_hash": head_hash,
        "created_at": datetime.now(UTC).isoformat(),
        "key_id": key_id,
        "previous_seal": previous["seal"] if previous else "0" * 64,
        "anchored_from": previous["anchored_from"] if previous else count,
    }
    entry["seal"] = hmac.new(key, _payload(entry), hashlib.sha256).hexdigest()
    with path.open("a", encoding="utf-8") as journal:
        journal.write(json.dumps(entry, sort_keys=True) + "\n")
        journal.flush()
        os.fsync(journal.fileno())


def reconcile_checkpoint(count: int, head_hash: str, reason: str, expected_seal: str,
                         key_id: str, key: bytes, keyring: dict[str, bytes]) -> None:
    """Explicitly start a new epoch after an authorized backup restore.

    The old journal is retained and linked, never removed or overwritten.
    A trusted operator supplies the seal they observed before reconciliation.
    """
    path = checkpoint_path()
    if path is None:
        raise RuntimeError("Audit checkpoint path is not configured")
    records, error = read_checkpoints(keyring)
    if error or not records:
        raise RuntimeError(f"Cannot reconcile checkpoint journal: {error}")
    previous = records[-1]
    if not hmac.compare_digest(previous["seal"], expected_seal):
        raise RuntimeError("Expected checkpoint seal does not match current journal")
    if not reason.strip():
        raise RuntimeError("A restore reason is required")
    entry = {
        "kind": "reconcile",
        "epoch": uuid.uuid4().hex,
        "previous_epoch": previous["epoch"],
        "previous_count": previous["count"],
        "previous_head_hash": previous["head_hash"],
        "reason": reason.strip(),
        "count": count,
        "head_hash": head_hash,
        "created_at": datetime.now(UTC).isoformat(),
        "key_id": key_id,
        "previous_seal": previous["seal"],
        "anchored_from": count,
    }
    entry["seal"] = hmac.new(key, _payload(entry), hashlib.sha256).hexdigest()
    with path.open("a", encoding="utf-8") as journal:
        journal.write(json.dumps(entry, sort_keys=True) + "\n")
        journal.flush()
        os.fsync(journal.fileno())

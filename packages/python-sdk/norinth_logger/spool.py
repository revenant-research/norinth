# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""where undelivered batches wait

delivery is fail-open: the SDK never blocks the host application, so a batch
that fails every retry either goes somewhere or is lost. by default it goes to
a private per-service directory on local disk and is resent on a later flush.
the operator can point the spool elsewhere (NORINTH_SPOOL_DIR=/path), switch
it off (NORINTH_SPOOL_DIR=off), or make a missing spool a startup failure
(NORINTH_DURABLE=true)
"""

from __future__ import annotations

import hashlib
import os
import tempfile

from .config import NorinthConfig

SPOOL_OFF = "off"


def resolve_spool_dir(config: NorinthConfig) -> str | None:
    """the directory undelivered batches are written to, or None when they will be dropped"""
    explicit = (config.spool_dir or "").strip()
    if explicit.lower() == SPOOL_OFF:
        return None
    if explicit:
        return explicit
    if config.capture_content:
        # with content capture on, a batch holds raw prompts and responses.
        # those never land on disk in a place the operator did not choose
        return None
    for base, path in default_spool_candidates(config):
        if _prepare_private_dir(base, path):
            return path
    return None


def spool_off_reason(config: NorinthConfig) -> str:
    """why resolve_spool_dir returned None, in one line, with the fix"""
    explicit = (config.spool_dir or "").strip()
    if explicit.lower() == SPOOL_OFF:
        return "spooling is switched off (NORINTH_SPOOL_DIR=off)"
    if config.capture_content:
        return (
            "content capture is on, so undelivered batches are not written to a default "
            "location; set NORINTH_SPOOL_DIR to a directory you control"
        )
    return "no writable spool directory was found; set NORINTH_SPOOL_DIR to a writable directory"


def default_spool_candidates(config: NorinthConfig) -> list[tuple[str, str]]:
    """(base, spool path) pairs in preference order

    the leaf is keyed by endpoint, api key and service, so two services on one
    host, or one service re-pointed at another instance, never drain each
    other's batches under the wrong key. the key is hashed, never written
    """
    ident = hashlib.sha256(f"{config.endpoint}\n{config.api_key}\n{config.service}".encode()).hexdigest()[:16]
    candidates: list[tuple[str, str]] = []
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        candidates.append((state_home, os.path.join(state_home, "norinth", "spool", ident)))
    home = os.path.expanduser("~")
    if home and home != "~":
        base = os.path.join(home, ".local", "state")
        candidates.append((base, os.path.join(base, "norinth", "spool", ident)))
    tmp = tempfile.gettempdir()
    candidates.append((tmp, os.path.join(tmp, f"norinth-{_uid()}", "spool", ident)))
    return candidates


def _uid() -> str:
    try:
        return str(os.getuid())
    except AttributeError:  # windows
        return os.environ.get("USERNAME") or "user"


def _prepare_private_dir(base: str, path: str) -> bool:
    """create path below base, owner-only, and prove it is writable"""
    try:
        os.makedirs(path, exist_ok=True)
        # every layout is base/<vendor>/<spool>/<ident>; keep all three private
        # so a shared temp dir does not expose another user's batches
        current = path
        for _ in range(3):
            if current == base:
                break
            try:
                os.chmod(current, 0o700)
            except OSError:
                pass
            current = os.path.dirname(current)
        probe = os.path.join(path, f".probe-{os.getpid()}")
        with open(probe, "wb") as handle:
            handle.write(b"")
        os.remove(probe)
        return True
    except OSError:
        return False

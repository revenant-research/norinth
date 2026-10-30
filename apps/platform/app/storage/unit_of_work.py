# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""one transaction for a governance mutation and the audit entry that describes it

a route that approves a gate, closes an incident or changes a control used
to save the change in one transaction and append the audit entry in another.
if the append failed (an integrity check on the chain, a database error) the
change stayed and the record of it was never written. inside a unit of work
every storage function writes on the unit's connection, the audit append
joins the same transaction, and the two commit or roll back together.

the audit checkpoint journal is a file, not a table, so its append and the
audit stream line run after the commit; a unit that rolls back leaves both
untouched
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

from . import db
from .audit_checkpoint import checkpoint_lock


class UnitOfWork:
    def __init__(self, connection) -> None:
        self.connection = connection
        self._after_commit: list[Callable[[], None]] = []
        self._after_rollback: list[Callable[[], None]] = []

    def after_commit(self, callback: Callable[[], None]) -> None:
        """run once the unit has committed, in registration order"""
        self._after_commit.append(callback)

    def after_rollback(self, callback: Callable[[], None]) -> None:
        self._after_rollback.append(callback)


@contextmanager
def unit_of_work() -> Iterator[UnitOfWork]:
    """run the block in one transaction; a unit inside a unit joins it

    the checkpoint journal lock is taken before the database write lock, the
    same order a lone audit append takes them, so a unit and a lone append can
    never wait on each other. on sqlite the transaction is IMMEDIATE, a write
    transaction from the start, so the chain read inside it cannot be invalidated
    by another writer; on postgres the audit append takes the chain's advisory
    lock inside the unit's transaction as it always has
    """
    existing = db.current_unit()
    if existing is not None:
        yield existing
        return
    with ExitStack() as held:
        held.enter_context(checkpoint_lock())
        connection = db.open_connection()
        connection.isolation_level = None  # the unit manages the transaction explicitly
        unit = UnitOfWork(connection)
        token = db.enter_unit(unit)
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield unit
            except BaseException:
                connection.rollback()
                raise
            connection.commit()
            committed = True
        finally:
            db.leave_unit(token)
            connection.close()
            if not committed:
                for callback in unit._after_rollback:
                    callback()
        # still under the journal lock: the journal append that follows a
        # commit stays ordered with every other append
        for callback in unit._after_commit:
            callback()


def atomic(handler: Callable[..., Any]) -> Callable[..., Any]:
    """run a route handler inside one unit of work

    for handlers that change a governance record and audit the change. not for
    handlers that deliberately persist something and then fail the request,
    such as a login attempt that records its own failure: those keep their
    write-then-raise order
    """

    @functools.wraps(handler)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        with unit_of_work():
            return handler(*args, **kwargs)

    return wrapped

from __future__ import annotations


class RecordNotFound(ValueError):
    """A record addressed by id does not exist.

    Subclasses ValueError so existing ``except ValueError`` sites keep working,
    while a dedicated type lets the API map "not found" to HTTP 404 instead of an
    unhandled 500 (audit finding M104).
    """

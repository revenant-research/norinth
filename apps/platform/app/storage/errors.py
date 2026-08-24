from __future__ import annotations


class RecordNotFound(ValueError):
    """a record addressed by id does not exist

    subclasses ValueError so existing except-ValueError sites keep working, while
    a dedicated type lets the api map not-found to 404 instead of a 500
    """

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations


class RecordNotFound(ValueError):
    """a record addressed by id does not exist

    subclasses ValueError so existing except-ValueError sites keep working, while
    a dedicated type lets the api map not-found to 404 instead of a 500
    """


class DomainError(ValueError):
    """an invalid request the caller can act on

    the api returns this message to the caller verbatim, so raise it only with
    text written for them. a bare ValueError from anywhere else - a coercion, a
    library, an internal invariant - is logged and answered with a generic
    message instead, so its wording never reaches the wire
    """

"""Uniform server-side pagination for list endpoints.

Endpoints accept ``offset`` and ``limit`` query
parameters and return, alongside the existing list key, a ``page`` object with
``offset``, ``limit``, ``total`` and ``has_more`` so API consumers and the UI can
page. The default limit is bounded; the maximum is capped.
"""

from __future__ import annotations

from typing import Any

from fastapi import Query

DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


class PageParams:
    """FastAPI dependency: ``?offset=&limit=`` with bounds enforced."""

    def __init__(
        self,
        offset: int = Query(0, ge=0, description="Zero-based index of the first item"),
        limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Maximum items to return"),
    ) -> None:
        self.offset = offset
        self.limit = limit


def paginate(payload: dict[str, Any], key: str, page: PageParams) -> dict[str, Any]:
    """Slice ``payload[key]`` by the page and attach ``page`` metadata.

    Keeps the original list key so existing clients keep working; they simply
    receive the first page plus the total.
    """
    items = payload.get(key) or []
    total = len(items)
    window = items[page.offset : page.offset + page.limit]
    return {
        **payload,
        key: window,
        "page": {
            "offset": page.offset,
            "limit": page.limit,
            "total": total,
            "has_more": page.offset + len(window) < total,
        },
    }

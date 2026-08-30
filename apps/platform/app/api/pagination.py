# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""server-side pagination for list endpoints"""

from __future__ import annotations

from typing import Any

from fastapi import Query

DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


class PageParams:
    """fastapi dependency for ?offset=&limit= with bounds"""

    def __init__(
        self,
        offset: int = Query(0, ge=0, description="Zero-based index of the first item"),
        limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Maximum items to return"),
    ) -> None:
        self.offset = offset
        self.limit = limit


def paginate(payload: dict[str, Any], key: str, page: PageParams) -> dict[str, Any]:
    """slice payload[key] by the page and attach page metadata"""
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

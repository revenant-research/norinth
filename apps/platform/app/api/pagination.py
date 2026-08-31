# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""server-side pagination for list endpoints"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Query

from app.schemas.events import ScopeFilter

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


def paged(
    build: Callable[..., dict[str, Any]],
    key: str,
    scope: ScopeFilter,
    page: PageParams,
    count: Callable[..., int],
) -> dict[str, Any]:
    """one page from a builder, with the page metadata attached

    both the builder and the count push the scope into sql. this used to fetch
    every row and slice the result in python, so the page parameters shaped the
    response without reducing the work and a paged request cost the same as an
    unpaged one
    """
    payload = build(scope, limit=page.limit, offset=page.offset)
    total = count(**scope.model_dump())
    rows = payload.get(key) or []
    return {
        **payload,
        "page": {
            "offset": page.offset,
            "limit": page.limit,
            "total": total,
            "has_more": page.offset + len(rows) < total,
        },
    }

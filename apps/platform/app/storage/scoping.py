# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""one scoped read for the tenant/project/environment tables

four storage modules each carried their own copy of this with drifting
signatures - two made tenant_id optional, two required it, and the order_by
defaults differed. these helpers are what apply tenant scoping, so drift between
copies is the kind that matters. limit and offset are applied in sql: the list
routes used to fetch every row and slice the result, so a paged request cost the
same as an unpaged one
"""

from __future__ import annotations

from typing import Any

from .raw_events import connect


def scope_clause(
    tenant_id: str | None,
    project: str | None,
    environment: str | None,
    extra_clause: str | None = None,
    extra_params: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = dict(extra_params or {})
    if extra_clause:
        clauses.append(extra_clause)
    if tenant_id:
        clauses.append("tenant_id = :tenant_id")
        params["tenant_id"] = tenant_id
    if project:
        clauses.append("project = :project")
        params["project"] = project
    if environment:
        clauses.append("environment = :environment")
        params["environment"] = environment
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def scoped_rows(
    table: str,
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    order_by: str,
    limit: int | None = None,
    offset: int = 0,
    extra_clause: str | None = None,
    extra_params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """rows for a scope, newest first by order_by

    table, order_by and extra_clause are module constants, never caller input;
    values belong in extra_params so they stay bound
    """
    where, params = scope_clause(tenant_id, project, environment, extra_clause, extra_params)
    window = ""
    if limit is not None:
        window = " LIMIT :limit OFFSET :offset"
        params = {**params, "limit": limit, "offset": offset}
    with connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM {table} {where} ORDER BY {order_by} DESC{window}", params
        ).fetchall()
    return [dict(row) for row in rows]


def count_scoped_rows(
    table: str,
    *,
    tenant_id: str | None = None,
    project: str | None = None,
    environment: str | None = None,
    extra_clause: str | None = None,
    extra_params: dict[str, Any] | None = None,
) -> int:
    where, params = scope_clause(tenant_id, project, environment, extra_clause, extra_params)
    with connect() as connection:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {table} {where}", params).fetchone()
    return int(row["count"])

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""vendor evidence references that expire

a vendor's claims (a signed BAA, a DPA, a SOC 2 report, an ISO/IEC 42001
certificate, a regulatory clearance) are recorded as typed references: a kind,
a name, an identifier, an issue date, an expiry date and an optional hash of
the document. never the document, never a questionnaire. the maintenance
worker ages the expiry dates: an expired reference drops the vendor to
recertify_due, which reopens the unreviewed-vendor finding on every system
using its providers, and the vendor cannot be approved again until a current
reference replaces the expired one and the review runs again
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .entities import entity_id
from .errors import DomainError, RecordNotFound
from .raw_events import connect

EVIDENCE_KINDS: dict[str, str] = {
    "baa": "Business associate agreement",
    "dpa": "Data processing agreement",
    "soc2_type2": "SOC 2 Type II report",
    "iso_27001": "ISO/IEC 27001 certificate",
    "iso_42001": "ISO/IEC 42001 certificate",
    "fda_clearance": "FDA clearance or approval",
    "pen_test": "Penetration test attestation",
    "other": "Other attestation",
}

# a reference whose expiry falls inside this window is announced once, so the
# renewal can be arranged before coverage lapses
EXPIRY_NOTICE_DAYS = 30

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACTIVE_STATUSES = ("current", "expired")


def ensure_vendor_evidence_tables(connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS vendor_evidence_references (
            reference_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            vendor_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            identifier TEXT,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            document_hash TEXT,
            status TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expired_at TEXT,
            expiry_notice_sent_at TEXT
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_vendor_evidence_vendor ON vendor_evidence_references(vendor_id, status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_vendor_evidence_tenant ON vendor_evidence_references(tenant_id, status, expires_at)"
    )


def _today() -> date:
    return datetime.now(UTC).date()


def _parse_date(value: Any, field: str) -> date:
    try:
        return date.fromisoformat(str(value).strip())
    except (TypeError, ValueError) as error:
        raise DomainError(f"{field} must be a date (YYYY-MM-DD)") from error


def _reference_row(row: Any) -> dict[str, Any]:
    record = dict(row)
    record["kind_label"] = EVIDENCE_KINDS.get(record["kind"], record["kind"])
    return record


def _vendor_in_tenant(connection, vendor_id: str, tenant_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT vendor_id, name, status FROM vendor_registry WHERE vendor_id = ? AND tenant_id = ?",
        (vendor_id, tenant_id),
    ).fetchone()
    if row is None:
        raise RecordNotFound("vendor not found in this organization")
    return dict(row)


def record_evidence_reference(
    *,
    tenant_id: str,
    vendor_id: str,
    kind: str,
    name: str,
    identifier: str | None,
    issued_at: str,
    expires_at: str,
    document_hash: str | None,
    actor_ref: str,
) -> dict[str, Any]:
    """record a reference; an earlier reference of the same kind for the vendor
    is superseded, so a renewed agreement replaces the one that lapsed"""
    if kind not in EVIDENCE_KINDS:
        raise DomainError(f"kind must be one of {', '.join(sorted(EVIDENCE_KINDS))}")
    issued = _parse_date(issued_at, "issued_at")
    expires = _parse_date(expires_at, "expires_at")
    if expires <= issued:
        raise DomainError("expires_at must be after issued_at")
    if expires <= _today():
        raise DomainError("expires_at must be in the future; a lapsed document is not evidence")
    if document_hash is not None:
        document_hash = document_hash.strip().lower()
        if not _SHA256.match(document_hash):
            raise DomainError("document_hash must be the hex SHA-256 of the document")
    label = name.strip()
    if not label:
        raise DomainError("name is required")
    reference_id = entity_id(
        "vendor-evidence", tenant_id, vendor_id, kind, issued.isoformat(), expires.isoformat(), label
    )
    with connect() as connection:
        vendor = _vendor_in_tenant(connection, vendor_id, tenant_id)
        if vendor["status"] == "retired":
            raise DomainError("a retired vendor takes no new evidence")
        connection.execute(
            """
            UPDATE vendor_evidence_references
            SET status = 'superseded', updated_at = datetime('now')
            WHERE vendor_id = ? AND kind = ? AND status IN ('current', 'expired') AND reference_id != ?
            """,
            (vendor_id, kind, reference_id),
        )
        connection.execute(
            """
            INSERT INTO vendor_evidence_references (
                reference_id, tenant_id, vendor_id, kind, name, identifier, issued_at, expires_at,
                document_hash, status, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'current', ?, datetime('now'), datetime('now'))
            ON CONFLICT (reference_id) DO UPDATE SET
                identifier = excluded.identifier,
                document_hash = excluded.document_hash,
                status = 'current',
                expired_at = NULL,
                expiry_notice_sent_at = NULL,
                updated_at = datetime('now')
            """,
            (
                reference_id,
                tenant_id,
                vendor_id,
                kind,
                label,
                (identifier or "").strip() or None,
                issued.isoformat(),
                expires.isoformat(),
                document_hash,
                actor_ref,
            ),
        )
        return _reference_row(
            connection.execute(
                "SELECT * FROM vendor_evidence_references WHERE reference_id = ?", (reference_id,)
            ).fetchone()
        )


def withdraw_evidence_reference(reference_id: str, tenant_id: str) -> dict[str, Any]:
    """a reference recorded in error, or one the vendor has revoked"""
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM vendor_evidence_references WHERE reference_id = ? AND tenant_id = ?",
            (reference_id, tenant_id),
        ).fetchone()
        if row is None:
            raise RecordNotFound("evidence reference not found in this organization")
        connection.execute(
            "UPDATE vendor_evidence_references SET status = 'withdrawn', updated_at = datetime('now') WHERE reference_id = ?",
            (reference_id,),
        )
        return _reference_row(
            connection.execute(
                "SELECT * FROM vendor_evidence_references WHERE reference_id = ?", (reference_id,)
            ).fetchone()
        )


def list_evidence_references(tenant_id: str, vendor_id: str | None = None) -> list[dict[str, Any]]:
    clauses = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if vendor_id is not None:
        clauses.append("vendor_id = ?")
        params.append(vendor_id)
    with connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM vendor_evidence_references WHERE {' AND '.join(clauses)} ORDER BY vendor_id, kind, expires_at DESC",
            tuple(params),
        ).fetchall()
    return [_reference_row(row) for row in rows]


def expired_references(connection, vendor_id: str) -> list[dict[str, Any]]:
    """references that have lapsed and were neither replaced nor withdrawn; while
    one stands the vendor's review cannot approve it"""
    rows = connection.execute(
        "SELECT * FROM vendor_evidence_references WHERE vendor_id = ? AND status = 'expired' ORDER BY kind",
        (vendor_id,),
    ).fetchall()
    return [_reference_row(row) for row in rows]


def require_no_expired_evidence(connection, vendor_id: str, vendor_name: str) -> None:
    lapsed = expired_references(connection, vendor_id)
    if lapsed:
        kinds = ", ".join(f"{item['kind_label']} ({item['name']}, expired {item['expires_at']})" for item in lapsed)
        raise DomainError(
            f"vendor '{vendor_name}' has expired evidence: {kinds}. Record a current reference or withdraw the "
            "expired one before the vendor can be approved"
        )


def age_evidence_references(now: datetime | None = None) -> dict[str, int]:
    """run by the maintenance worker

    a current reference past its expiry date becomes expired. an approved
    vendor holding one drops to recertify_due, which reopens the unreviewed
    vendor finding on every system using its providers. a reference inside the
    notice window is announced once
    """
    from app.services.notifications import emit, public_base_url

    from .audit import record_audit
    from .policy_engine import refresh_vendor_posture

    today = (now or datetime.now(UTC)).date()
    notice_edge = today + timedelta(days=EXPIRY_NOTICE_DAYS)
    expired: list[dict[str, Any]] = []
    flipped: list[dict[str, Any]] = []
    warned: list[dict[str, Any]] = []
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT r.*, v.name AS vendor_name, v.status AS vendor_status
            FROM vendor_evidence_references r
            JOIN vendor_registry v ON v.vendor_id = r.vendor_id
            WHERE r.status = 'current' AND r.expires_at <= ?
            ORDER BY r.tenant_id, r.vendor_id, r.kind
            """,
            (notice_edge.isoformat(),),
        ).fetchall()
        for row in rows:
            reference = _reference_row(row)
            lapsed = date.fromisoformat(reference["expires_at"]) < today
            if lapsed:
                connection.execute(
                    "UPDATE vendor_evidence_references SET status = 'expired', expired_at = datetime('now'), "
                    "updated_at = datetime('now') WHERE reference_id = ? AND status = 'current'",
                    (reference["reference_id"],),
                )
                expired.append(reference)
                moved = connection.execute(
                    "UPDATE vendor_registry SET status = 'recertify_due', updated_at = datetime('now') "
                    "WHERE vendor_id = ? AND status = 'approved'",
                    (reference["vendor_id"],),
                )
                if getattr(moved, "rowcount", 0) > 0:
                    flipped.append(reference)
                emit(
                    connection,
                    tenant_id=reference["tenant_id"],
                    event_type="vendor.evidence_expired",
                    subject=f"Vendor evidence expired: {reference['vendor_name']} {reference['kind_label']}",
                    text=(
                        f"The {reference['kind_label']} '{reference['name']}' for vendor '{reference['vendor_name']}' "
                        f"expired on {reference['expires_at']}. Until a current reference is recorded and the vendor "
                        "is re-reviewed, its providers count as unreviewed in the risk register."
                    ),
                    data={
                        "vendor_id": reference["vendor_id"],
                        "reference_id": reference["reference_id"],
                        "kind": reference["kind"],
                        "expires_at": reference["expires_at"],
                    },
                    to_roles=["org_admin", "governance_reviewer"],
                    link=f"{public_base_url()}/#vendors",
                )
            elif reference.get("expiry_notice_sent_at") is None:
                connection.execute(
                    "UPDATE vendor_evidence_references SET expiry_notice_sent_at = datetime('now') WHERE reference_id = ?",
                    (reference["reference_id"],),
                )
                warned.append(reference)
                emit(
                    connection,
                    tenant_id=reference["tenant_id"],
                    event_type="vendor.evidence_expiring",
                    subject=f"Vendor evidence expires soon: {reference['vendor_name']} {reference['kind_label']}",
                    text=(
                        f"The {reference['kind_label']} '{reference['name']}' for vendor '{reference['vendor_name']}' "
                        f"expires on {reference['expires_at']}. Arrange the renewal and record the new reference "
                        "before then, or the vendor's approval lapses."
                    ),
                    data={
                        "vendor_id": reference["vendor_id"],
                        "reference_id": reference["reference_id"],
                        "kind": reference["kind"],
                        "expires_at": reference["expires_at"],
                    },
                    to_roles=["org_admin"],
                    link=f"{public_base_url()}/#vendors",
                )
    for reference in expired:
        record_audit(
            actor_ref="system:policy",
            action="vendor.evidence_expired",
            tenant_id=reference["tenant_id"],
            target_type="vendor_evidence",
            target_id=reference["reference_id"],
            detail={
                "vendor_id": reference["vendor_id"],
                "kind": reference["kind"],
                "expires_at": reference["expires_at"],
            },
        )
    for reference in flipped:
        record_audit(
            actor_ref="system:policy",
            action="vendor.recertify_due",
            tenant_id=reference["tenant_id"],
            target_type="vendor",
            target_id=reference["vendor_id"],
            detail={
                "name": reference["vendor_name"],
                "reason": "evidence_expired",
                "reference_id": reference["reference_id"],
            },
        )
    if flipped:
        # the findings on every dependent system open now, not at the next ingest
        refresh_vendor_posture(sorted({reference["tenant_id"] for reference in flipped}))
    return {"expired": len(expired), "vendors_due": len(flipped), "warned": len(warned)}

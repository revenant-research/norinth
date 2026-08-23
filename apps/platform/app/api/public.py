"""unauthenticated endpoints for the public landing page"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.api.auth import client_ip
from app.storage.leads import INTERESTS, count_leads_from_ip, create_lead

router = APIRouter()

LEADS_PER_IP_PER_DAY = 10
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


class LeadRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=254)
    organization: str = Field(min_length=1, max_length=200)
    interest: str = Field(default="pilot", max_length=40)
    message: str | None = Field(default=None, max_length=4000)

    @field_validator("email")
    @classmethod
    def _email_shape(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL.match(value):
            raise ValueError("enter a valid email address")
        return value


@router.post("/api/public/leads", status_code=201)
def submit_lead(payload: LeadRequest, request: Request) -> dict[str, Any]:
    if payload.interest not in INTERESTS:
        raise HTTPException(status_code=400, detail=f"interest must be one of {sorted(INTERESTS)}")
    ip = client_ip(request) or "unknown"
    since = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    if count_leads_from_ip(ip, since) >= LEADS_PER_IP_PER_DAY:
        raise HTTPException(status_code=429, detail="Too many requests from this address. Please email us instead.")
    lead = create_lead(
        name=payload.name.strip(),
        email=payload.email,
        organization=payload.organization.strip(),
        interest=payload.interest,
        message=(payload.message or "").strip() or None,
        source_ip=ip,
    )
    # not written to the audit chain; anonymous submissions shouldn't grow a tamper-evident log
    return {"ok": True, "lead_id": lead["lead_id"]}

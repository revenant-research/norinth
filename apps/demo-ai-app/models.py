"""Domain and API models for the Helpdesk Assistant service.

The request models carry ``tenant_id`` and ``user_id`` because this is a
multi-tenant B2B service: callers identify the customer organization the work
belongs to and the support agent performing it. These are product authorization
and data-scoping fields, not telemetry plumbing.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class TicketMessage(BaseModel):
    author: str
    body: str


class Ticket(BaseModel):
    ticket_id: str
    subject: str
    priority: str
    status: str
    customer_email: str
    messages: list[TicketMessage]


class AssistRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    guidance: str | None = None


class SummaryResponse(BaseModel):
    ticket_id: str
    summary: str
    model: str


class ReplyResponse(BaseModel):
    ticket_id: str
    reply: str
    model: str


class TriageResponse(BaseModel):
    ticket_id: str
    recommended_priority: str
    reasoning: str
    model: str

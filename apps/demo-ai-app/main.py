"""Helpdesk Assistant service.

A small multi-tenant support API that uses LLMs to summarize tickets, draft
replies, and recommend a priority. The business logic in this file knows nothing
about Norinth; observability is added in a single line below and can be removed
without affecting behavior.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

import observability
from assistant import SupportAssistant
from config import load_config
from models import AssistRequest, ReplyResponse, SummaryResponse, Ticket, TriageResponse
from store import TicketStore

config = load_config()
store = TicketStore()
assistant = SupportAssistant(config)

app = FastAPI(title="Helpdesk Assistant")

# --- Norinth observability. This single line is the only telemetry touch-point
# in the service. Removing it leaves every endpoint below unchanged. ---
observability.install(app)


def _require_ticket(tenant_id: str, ticket_id: str) -> Ticket:
    ticket = store.get(tenant_id, ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


def _provider_error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=502, detail=f"Model provider error: {exc}")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/tickets/{ticket_id}", response_model=Ticket)
def get_ticket(ticket_id: str, tenant_id: str) -> Ticket:
    return _require_ticket(tenant_id, ticket_id)


@app.post("/v1/tickets/{ticket_id}/summary", response_model=SummaryResponse)
def summarize_ticket(ticket_id: str, request: AssistRequest) -> SummaryResponse:
    ticket = _require_ticket(request.tenant_id, ticket_id)
    try:
        summary, model = assistant.summarize(ticket, request.guidance)
    except Exception as exc:  # noqa: BLE001 - surface provider failures to the caller
        raise _provider_error(exc)
    return SummaryResponse(ticket_id=ticket.ticket_id, summary=summary, model=model)


@app.post("/v1/tickets/{ticket_id}/suggested-reply", response_model=ReplyResponse)
def suggested_reply(ticket_id: str, request: AssistRequest) -> ReplyResponse:
    ticket = _require_ticket(request.tenant_id, ticket_id)
    try:
        reply, model = assistant.draft_reply(ticket, request.guidance)
    except Exception as exc:  # noqa: BLE001 - surface provider failures to the caller
        raise _provider_error(exc)
    return ReplyResponse(ticket_id=ticket.ticket_id, reply=reply, model=model)


@app.post("/v1/tickets/{ticket_id}/triage", response_model=TriageResponse)
def triage_ticket(ticket_id: str, request: AssistRequest) -> TriageResponse:
    ticket = _require_ticket(request.tenant_id, ticket_id)
    try:
        priority, reasoning, model = assistant.recommend_priority(ticket)
    except Exception as exc:  # noqa: BLE001 - surface provider failures to the caller
        raise _provider_error(exc)
    return TriageResponse(ticket_id=ticket.ticket_id, recommended_priority=priority, reasoning=reasoning, model=model)

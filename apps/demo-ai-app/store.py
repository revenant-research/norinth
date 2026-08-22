"""In-memory ticket store.

A real deployment would back this with a database. For the demo it ships with a
handful of tickets per tenant so the AI endpoints have something to work on.
"""

from __future__ import annotations

from models import Ticket, TicketMessage

_TICKETS: dict[str, dict[str, Ticket]] = {
    "acme": {
        "T-1001": Ticket(
            ticket_id="T-1001",
            subject="Cannot log in after password reset",
            priority="normal",
            status="open",
            customer_email="dana@acme-customer.example",
            messages=[
                TicketMessage(author="customer", body="I reset my password but the login page keeps rejecting it."),
                TicketMessage(author="customer", body="I tried two browsers and clearing my cache. Still no luck."),
            ],
        ),
        "T-1002": Ticket(
            ticket_id="T-1002",
            subject="Billing charged twice this month",
            priority="high",
            status="open",
            customer_email="mo@acme-customer.example",
            messages=[
                TicketMessage(author="customer", body="My card was charged twice for the September invoice."),
                TicketMessage(author="agent", body="Thanks for flagging, looking into the duplicate charge now."),
            ],
        ),
    },
    "globex": {
        "T-2001": Ticket(
            ticket_id="T-2001",
            subject="API returning 500 on bulk export",
            priority="urgent",
            status="open",
            customer_email="lee@globex-customer.example",
            messages=[
                TicketMessage(author="customer", body="Bulk export has been failing with a 500 since this morning."),
            ],
        ),
    },
}


class TicketStore:
    def get(self, tenant_id: str, ticket_id: str) -> Ticket | None:
        return _TICKETS.get(tenant_id, {}).get(ticket_id)

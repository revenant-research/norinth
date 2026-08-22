"""Support assistant business logic.

This module talks to model providers directly through their official SDKs, the
way any application would. It has no knowledge of Norinth or telemetry: the
provider calls below are captured automatically once observability is installed
in ``main.py``.
"""

from __future__ import annotations

from config import AppConfig
from models import Ticket


def _format_thread(ticket: Ticket) -> str:
    lines = [f"Subject: {ticket.subject}", f"Priority: {ticket.priority}", ""]
    for message in ticket.messages:
        lines.append(f"{message.author}: {message.body}")
    return "\n".join(lines)


class SupportAssistant:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._openai_client = None
        self._anthropic_client = None

    def _openai(self):
        if self._openai_client is None:
            from openai import OpenAI

            self._openai_client = OpenAI(api_key=self._config.openai_api_key)
        return self._openai_client

    def _anthropic(self):
        if self._anthropic_client is None:
            from anthropic import Anthropic

            self._anthropic_client = Anthropic(api_key=self._config.anthropic_api_key)
        return self._anthropic_client

    def summarize(self, ticket: Ticket, guidance: str | None) -> tuple[str, str]:
        instruction = guidance or "Summarize the conversation and list the next action for the agent."
        prompt = (
            "You are a support operations assistant. "
            f"{instruction}\n\n{_format_thread(ticket)}"
        )
        response = self._openai().responses.create(model=self._config.openai_model, input=prompt)
        return _openai_text(response), self._config.openai_model

    def draft_reply(self, ticket: Ticket, guidance: str | None) -> tuple[str, str]:
        instruction = guidance or "Draft a concise, friendly reply that moves the ticket toward resolution."
        prompt = (
            "You are a customer support agent. "
            f"{instruction}\n\n{_format_thread(ticket)}"
        )
        response = self._openai().responses.create(model=self._config.openai_model, input=prompt)
        return _openai_text(response), self._config.openai_model

    def recommend_priority(self, ticket: Ticket) -> tuple[str, str, str]:
        prompt = (
            "Classify the support ticket below into one of: low, normal, high, urgent. "
            "Respond with the priority on the first line and a one-sentence reason on the second.\n\n"
            f"{_format_thread(ticket)}"
        )
        message = self._anthropic().messages.create(
            model=self._config.anthropic_model,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        text = _anthropic_text(message)
        priority, _, reasoning = text.partition("\n")
        return priority.strip().lower() or "normal", reasoning.strip() or text, self._config.anthropic_model


def _openai_text(response: object) -> str:
    text = getattr(response, "output_text", None)
    if text:
        return text
    return str(response)


def _anthropic_text(message: object) -> str:
    blocks = getattr(message, "content", None) or []
    parts = [getattr(block, "text", "") for block in blocks]
    return "\n".join(part for part in parts if part).strip()

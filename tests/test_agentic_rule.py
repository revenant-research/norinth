"""agentic-workflow risk rule matches whole words not substrings"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage.governance_policy import _AGENTIC_TERMS  # noqa: E402


def test_substring_does_not_match():
    assert _AGENTIC_TERMS.search("stool-sample-tracker") is None
    assert _AGENTIC_TERMS.search("management console") is None
    assert _AGENTIC_TERMS.search("catalog of tolls") is None


def test_whole_word_agentic_terms_match():
    assert _AGENTIC_TERMS.search("customer support agent")
    assert _AGENTIC_TERMS.search("an agentic planner")
    assert _AGENTIC_TERMS.search("uses tools to act")
    assert _AGENTIC_TERMS.search("orchestrates a workflow")


def _model_call(app_name: str) -> dict:
    return {
        "type": "model.call",
        "status": "success",
        "attributes": {"provider": "openai", "model": "gpt-4o", "metadata": {"application_name": app_name}},
    }


def _tool_call(app_name: str) -> dict:
    return {
        "type": "tool.call",
        "status": "success",
        "attributes": {"metadata": {"application_name": app_name}},
    }


def _run_rule(app_name: str, events: list[dict]) -> bool:
    from app.storage.governance_policy import assess_risk_rules
    from app.storage.raw_events import connect

    rule = {
        "rule_id": "R-AGENT",
        "name": "Agentic workflow without agent run evidence",
        "signal": "missing_agent_run",
        "severity": "high",
        "rationale": "Agentic usage without agent.run telemetry.",
        "framework_refs": [],
    }
    app_context = {"tenant_id": "acme", "project": "p", "environment": "prod", "application_name": app_name}
    with connect() as connection:
        assess_risk_rules(connection, app_context, [rule], events)
        row = connection.execute(
            "SELECT COUNT(*) AS n FROM risk_findings WHERE application_name = ? AND rule_id = 'R-AGENT'",
            (app_name,),
        ).fetchone()
    return int(row["n"]) > 0


def test_stool_tracker_is_not_flagged(client):
    assert _run_rule("stool-sample-tracker", [_model_call("stool-sample-tracker")]) is False


def test_real_agentic_app_is_flagged(client):
    assert _run_rule("returns-agent", [_model_call("returns-agent")]) is True


def test_tool_call_telemetry_flags_regardless_of_name(client):
    # no agentic term in name but tool.call telemetry with no agent.run
    assert _run_rule("claims-copilot", [_model_call("claims-copilot"), _tool_call("claims-copilot")]) is True

import os
import time
import uuid

import norinth_logger as norinth

norinth.init(
    api_key=os.getenv("NORINTH_API_KEY", "dev"),
    endpoint=os.getenv("NORINTH_ENDPOINT", "http://127.0.0.1:8001"),
    project="norinth-sandbox",
    environment="sandbox",
    service="seed-script",
)
client = norinth.get_client()

# support copilot
trace_id_1 = f"trc-{uuid.uuid4().hex[:8]}"
span_id_1 = f"spn-{uuid.uuid4().hex[:8]}"
client.record(norinth.schemas.NorinthEvent(
    type="trace.completed",
    trace_id=trace_id_1,
    span_id=span_id_1,
    service="support-copilot",
    environment="sandbox",
    project="norinth-sandbox",
    system="fastapi",
    name="support.summary",
    status="success",
    duration_ms=1450,
    attributes={
        "metadata": {
            "synthetic": True,
            "user_id": "support-agent-42",
            "application_name": "Support Copilot",
            "workflow_name": "support.summary",
            "use_case": "Summarize customer support tickets",
            "model_purpose": "Draft concise summaries and next actions"
        }
    }
))
client.record(norinth.schemas.NorinthEvent(
    type="model.call",
    trace_id=trace_id_1,
    span_id=f"spn-{uuid.uuid4().hex[:8]}",
    parent_span_id=span_id_1,
    service="support-copilot",
    environment="sandbox",
    project="norinth-sandbox",
    system="fastapi",
    name="responses.create",
    status="success",
    duration_ms=1300,
    attributes={
        "provider": "openai",
        "model": "gpt-4o-mini",
        "operation": "responses.create",
        "prompt": "Summarize the ticket: Customer cannot login.",
        "response": "Customer is experiencing login issues. Recommended action: Send password reset link.",
        "usage": {"input_tokens": 120, "output_tokens": 45, "total_tokens": 165},
        "metadata": {
            "synthetic": True,
            "application_name": "Support Copilot",
            "workflow_name": "support.summary"
        }
    }
))

client.deployment(
    deployment_id="support-copilot-v2-1",
    version="v2.1",
    application_name="Support Copilot",
    workflow_name="support.summary",
    artifact_ref="git:support-copilot@v2.1",
    status="active",
    provider="openai",
    model="gpt-4o-mini",
    prompt_version="v2.0",
    metadata={"synthetic": True}
)

client.incident(
    incident_id=f"inc-{uuid.uuid4().hex[:8]}",
    title="Support Copilot Generating Inaccurate Summaries",
    severity="Medium",
    status="open",
    application_name="Support Copilot",
    workflow_name="support.summary",
    description="Agents report that summaries are omitting key context regarding escalated tickets.",
    impacted_trace_id=trace_id_1,
    metadata={"synthetic": True}
)

# agentic governance assistant
trace_id_2 = f"trc-{uuid.uuid4().hex[:8]}"
span_id_2 = f"spn-{uuid.uuid4().hex[:8]}"
client.record(norinth.schemas.NorinthEvent(
    type="trace.completed",
    trace_id=trace_id_2,
    span_id=span_id_2,
    service="agentic-governance-assistant",
    environment="sandbox",
    project="norinth-sandbox",
    system="fastapi",
    name="agentic.governance.review",
    status="success",
    duration_ms=4500,
    attributes={
        "metadata": {
            "synthetic": True,
            "user_id": "governance-admin",
            "application_name": "Agentic Governance Assistant",
            "workflow_name": "agentic.governance.review",
            "use_case": "Coordinate multi-provider governance review",
            "model_purpose": "Generate governance review evidence"
        }
    }
))

client.guardrail(
    guardrail_name="sensitive-context-check",
    decision="warn",
    score=0.8,
    matched_rules=["customer_data"],
    metadata={
        "synthetic": True,
        "application_name": "Agentic Governance Assistant",
        "workflow_name": "agentic.governance.review"
    }
)

client.eval_result(
    eval_name="governance-plan-completeness",
    score=0.95,
    threshold=0.6,
    passed=True,
    metadata={
        "synthetic": True,
        "application_name": "Agentic Governance Assistant",
        "workflow_name": "agentic.governance.review"
    }
)

client.agent_run(
    agent_name="governance-evidence-agent",
    steps=[
        {"name": "retrieve_context", "type": "retrieval", "documents": 4},
        {"name": "check_sensitive_context", "type": "guardrail", "decision": "warn"},
        {"name": "build_risk_profile", "type": "tool", "risk_level": "medium"},
        {"name": "analyze_risk", "type": "model_call", "provider": "anthropic", "model": "claude-haiku-4-5"},
        {"name": "build_controls", "type": "model_call", "provider": "openai", "model": "gpt-4o-mini"},
        {"name": "evaluate_plan", "type": "eval", "score": 0.95}
    ],
    outcome="governance review completed",
    duration_ms=4200,
    metadata={
        "synthetic": True,
        "application_name": "Agentic Governance Assistant",
        "workflow_name": "agentic.governance.review"
    }
)

client.deployment(
    deployment_id="agentic-gov-v1-0-rc",
    version="v1.0-rc",
    application_name="Agentic Governance Assistant",
    workflow_name="agentic.governance.review",
    artifact_ref="git:agentic-gov@v1.0-rc",
    status="pending_review",
    provider="multiple",
    model="multiple",
    prompt_version="v1.0",
    metadata={"synthetic": True}
)

client.shutdown()
time.sleep(1)

# report what actually happened instead of assuming success
stats = client.transport.stats
if stats.sent > 0 and stats.dropped == 0 and stats.failed_sends == 0:
    print(f"Seeded {stats.sent} synthetic sandbox events successfully.")
    raise SystemExit(0)

print(
    f"Seeding did not fully succeed: sent={stats.sent} "
    f"dropped={stats.dropped} failed_sends={stats.failed_sends}."
)
print("Check that the platform is running at the configured endpoint and that "
      "the dev ingestion key is seeded (NORINTH_DEV_MODE).")
raise SystemExit(1)

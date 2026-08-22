import time
import uuid

import norinth_logger as norinth

norinth.init(
    api_key="dev",
    endpoint="http://127.0.0.1:8001",
    project="norinth-sandbox",
    environment="production",
    service="seed-script",
)
client = norinth.get_client()

# Seed Support Copilot Data
trace_id_1 = f"trc-{uuid.uuid4().hex[:8]}"
span_id_1 = f"spn-{uuid.uuid4().hex[:8]}"
client.record(norinth.schemas.NorinthEvent(
    type="trace.completed",
    trace_id=trace_id_1,
    span_id=span_id_1,
    service="support-copilot",
    environment="production",
    project="norinth-sandbox",
    system="fastapi",
    name="support.summary",
    status="success",
    duration_ms=1450,
    attributes={
        "metadata": {
            "tenant_id": "tenant-verify",
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
    environment="production",
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
            "tenant_id": "tenant-verify",
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
    metadata={"tenant_id": "tenant-verify"}
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
    metadata={"tenant_id": "tenant-verify"}
)

# Seed Agentic Governance Assistant
trace_id_2 = f"trc-{uuid.uuid4().hex[:8]}"
span_id_2 = f"spn-{uuid.uuid4().hex[:8]}"
client.record(norinth.schemas.NorinthEvent(
    type="trace.completed",
    trace_id=trace_id_2,
    span_id=span_id_2,
    service="agentic-governance-assistant",
    environment="production",
    project="norinth-sandbox",
    system="fastapi",
    name="agentic.governance.review",
    status="success",
    duration_ms=4500,
    attributes={
        "metadata": {
            "tenant_id": "tenant-verify",
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
        "tenant_id": "tenant-verify",
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
        "tenant_id": "tenant-verify",
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
        "tenant_id": "tenant-verify",
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
    metadata={"tenant_id": "tenant-verify"}
)

client.shutdown()
time.sleep(1)
print("Enterprise data seeded successfully!")

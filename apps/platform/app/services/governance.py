from __future__ import annotations

from collections import Counter
from typing import Any

from app.schemas.events import Event, ScopeFilter
from app.storage.deployments import list_deployment_gates, list_deployment_versions, list_deployments
from app.storage.entities import (
    list_applications,
    list_controls,
    list_models,
    list_observed_events,
    list_providers,
    list_risks,
    list_workflows,
)
from app.storage.governance_policy import (
    list_configured_risk_rules,
    list_control_assessments,
    list_controls_catalog,
    list_risk_findings,
)
from app.storage.incidents import list_incidents
from app.storage.lifecycle import list_change_events, list_review_tasks
from app.storage.prompts import list_prompt_templates, list_prompt_versions
from app.storage.raw_events import (
    aggregate_traces,
    count_distinct,
    count_error_events,
    count_events_by_type,
    list_events,
)
from app.storage.workflow import (
    list_configured_owner_policies,
    list_decisions,
    list_exceptions,
    list_owner_assignments,
    list_platform_users,
    list_review_queue_policies,
    list_role_assignments,
)

# Page size used when a builder must aggregate over every matching event, and
# the safety ceiling on that scan. The old single 10,000-row window silently
# truncated aggregates (event/error counts, resource graph, per-model rollups)
# for any tenant past that size and reported "10,000" forever (audit finding H9).
_SCAN_PAGE = 5000
MAX_QUERY_LIMIT = 500_000


def scoped_events(scope: ScopeFilter, *, event_type: str | None = None, limit: int = MAX_QUERY_LIMIT) -> list[Event]:
    """All matching events (up to ``limit``), paged so aggregation builders are
    correct beyond a single query window. Prefer the SQL count/aggregate helpers
    for pure counts; this exists for builders that must parse event attributes."""
    events: list[Event] = []
    offset = 0
    while offset < limit:
        page = list_events(
            tenant_id=scope.tenant_id,
            project=scope.project,
            environment=scope.environment,
            event_type=event_type,
            limit=min(_SCAN_PAGE, limit - offset),
            offset=offset,
        )
        events.extend(Event.model_validate(event) for event in page)
        if len(page) < _SCAN_PAGE:
            break
        offset += _SCAN_PAGE
    return events


def event_attributes(event: Event) -> dict[str, Any]:
    return event.attributes or {}


def event_metadata(event: Event) -> dict[str, Any]:
    return event_attributes(event).get("metadata") or {}


def event_usage(event: Event) -> dict[str, Any]:
    return event_attributes(event).get("usage") or {}


def token_count(usage: dict[str, Any], field: str) -> int:
    return int(usage.get(field) or 0)


def build_systems(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    by_system: dict[str, dict[str, Any]] = {}
    for event in scoped_events(scope):
        system = event.system or event.service
        record = by_system.setdefault(
            system,
            {"system": system, "service": event.service, "environment": event.environment, "events": 0, "models": set(), "vendors": set()},
        )
        record["events"] += 1
        if event.type == "model.call":
            attrs = event_attributes(event)
            record["models"].add(attrs.get("model", "unknown"))
            record["vendors"].add(attrs.get("provider", "unknown"))

    return {
        "systems": [
            {**record, "models": sorted(record["models"]), "vendors": sorted(record["vendors"])}
            for record in by_system.values()
        ]
    }


def build_applications(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"applications": list_applications(**scope.model_dump())}


def build_workflows(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"workflows": list_workflows(**scope.model_dump())}


def build_models(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"models": list_models(**scope.model_dump())}


def build_retrievals(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {
        "retrievals": [
            {
                "time": event["observed_at"],
                "trace_id": event["trace_id"],
                "retriever": event["name"],
                "document_count": event["attributes"].get("document_count", 0),
                "workflow_name": event.get("workflow_name") or "unknown",
                "application_name": event.get("application_name") or "unknown",
                "status": event["status"],
                "duration_ms": event["duration_ms"],
            }
            for event in list_observed_events("retrieval.call", **scope.model_dump())
        ]
    }


def build_tools(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {
        "tools": [
            {
                "time": event["observed_at"],
                "trace_id": event["trace_id"],
                "tool_name": event["name"],
                "workflow_name": event.get("workflow_name") or "unknown",
                "application_name": event.get("application_name") or "unknown",
                "status": event["status"],
                "duration_ms": event["duration_ms"],
            }
            for event in list_observed_events("tool.call", **scope.model_dump())
        ]
    }


def build_guardrails(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {
        "guardrails": [
            {
                "time": event["observed_at"],
                "trace_id": event["trace_id"],
                "guardrail_name": event["name"],
                "decision": event["attributes"].get("decision", "unknown"),
                "score": event["attributes"].get("score"),
                "matched_rules": event["attributes"].get("matched_rules", []),
                "workflow_name": event.get("workflow_name") or "unknown",
                "application_name": event.get("application_name") or "unknown",
                "status": event["status"],
            }
            for event in list_observed_events("guardrail.decision", **scope.model_dump())
        ]
    }


def build_evals(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {
        "evals": [
            {
                "time": event["observed_at"],
                "trace_id": event["trace_id"],
                "eval_name": event["name"],
                "score": event["attributes"].get("score"),
                "threshold": event["attributes"].get("threshold"),
                "passed": event["attributes"].get("passed"),
                "attested": event["attributes"].get("attested") is True,
                "attested_key_id": event["attributes"].get("attested_key_id"),
                "workflow_name": event.get("workflow_name") or "unknown",
                "application_name": event.get("application_name") or "unknown",
                "status": event["status"],
            }
            for event in list_observed_events("eval.result", **scope.model_dump())
        ]
    }


def build_agents(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {
        "agents": [
            {
                "time": event["observed_at"],
                "trace_id": event["trace_id"],
                "agent_name": event["name"],
                "step_count": event["attributes"].get("step_count", 0),
                "outcome": event["attributes"].get("outcome", ""),
                "workflow_name": event.get("workflow_name") or "unknown",
                "application_name": event.get("application_name") or "unknown",
                "status": event["status"],
                "duration_ms": event["duration_ms"],
            }
            for event in list_observed_events("agent.run", **scope.model_dump())
        ]
    }


def build_resource_graph(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()

    def add_node(node_type: str, node_id: str, label: str) -> str:
        key = f"{node_type}:{node_id}"
        nodes.setdefault(key, {"id": key, "type": node_type, "label": label})
        return key

    for event in scoped_events(scope, event_type="model.call"):
        attrs = event_attributes(event)
        metadata = event_metadata(event)
        application_name = metadata.get("application_name", "unknown")
        workflow_name = metadata.get("workflow_name", event.name or "unknown")
        provider = attrs.get("provider", "unknown")
        model = attrs.get("model", "unknown")
        user_id = metadata.get("user_id", "unknown")

        app_node = add_node("application", application_name, application_name)
        workflow_node = add_node("workflow", workflow_name, workflow_name)
        provider_node = add_node("provider", provider, provider)
        model_node = add_node("model", f"{provider}:{model}", model)
        user_node = add_node("user", user_id, user_id)
        trace_node = add_node("trace", event.trace_id, event.trace_id)

        edges.update(
            {
                (user_node, "invoked", workflow_node),
                (app_node, "contains", workflow_node),
                (workflow_node, "called", model_node),
                (model_node, "served_by", provider_node),
                (workflow_node, "emitted_trace", trace_node),
            }
        )

    for event_type, node_type, relationship in (
        ("retrieval.call", "retriever", "retrieved_from"),
        ("tool.call", "tool", "used_tool"),
        ("guardrail.decision", "guardrail", "checked_by"),
        ("eval.result", "eval", "evaluated_by"),
        ("agent.run", "agent", "ran_agent"),
    ):
        for event in scoped_events(scope, event_type=event_type):
            attrs = event_attributes(event)
            metadata = event_metadata(event)
            workflow_name = metadata.get("workflow_name", event.name or "unknown")
            application_name = metadata.get("application_name", "unknown")
            app_node = add_node("application", application_name, application_name)
            workflow_node = add_node("workflow", workflow_name, workflow_name)
            observed_name = (
                attrs.get("retriever")
                or attrs.get("tool_name")
                or attrs.get("guardrail_name")
                or attrs.get("eval_name")
                or attrs.get("agent_name")
                or event.name
                or "unknown"
            )
            observed_node = add_node(node_type, str(observed_name), str(observed_name))
            trace_node = add_node("trace", event.trace_id, event.trace_id)
            edges.update(
                {
                    (app_node, "contains", workflow_node),
                    (workflow_node, relationship, observed_node),
                    (workflow_node, "emitted_trace", trace_node),
                }
            )

    return {
        "nodes": list(nodes.values()),
        "edges": [{"source": source, "relationship": relationship, "target": target} for source, relationship, target in sorted(edges)],
    }


def build_resource_graph_neighborhood(scope: ScopeFilter, node_id: str) -> dict[str, Any]:
    graph = build_resource_graph(scope)
    edges = [
        edge
        for edge in graph["edges"]
        if edge["source"] == node_id or edge["target"] == node_id
    ]
    connected_ids = {node_id}
    for edge in edges:
        connected_ids.add(edge["source"])
        connected_ids.add(edge["target"])
    return {
        "node_id": node_id,
        "nodes": [node for node in graph["nodes"] if node["id"] in connected_ids],
        "edges": edges,
    }


def build_application_detail(scope: ScopeFilter, application_id: str) -> dict[str, Any] | None:
    scope_kwargs = scope.model_dump()
    applications = list_applications(**scope_kwargs)
    application = find_record(applications, "entity_id", application_id)
    if application is None:
        return None

    application_name = application["application_name"]
    related_events = events_for_application(scope, application_name)
    trace_ids = sorted({event.trace_id for event in related_events})
    return {
        "application": application,
        "workflows": [
            workflow
            for workflow in list_workflows(**scope_kwargs)
            if application_name in workflow.get("applications", [])
        ],
        "models": [
            model
            for model in list_models(**scope_kwargs)
            if application_name in model.get("applications", [])
        ],
        "risks": [
            risk
            for risk in list_risk_findings(**scope_kwargs)
            if risk.get("application_name") == application_name
        ],
        "runtime_risks": [
            risk
            for risk in list_risks(**scope_kwargs)
            if risk.get("application_name") == application_name
        ],
        "controls": [
            control
            for control in list_control_assessments(**scope_kwargs)
            if control.get("application_name") == application_name
        ],
        "runtime_controls": list_controls(**scope_kwargs),
        "changes": [
            change
            for change in list_change_events(**scope_kwargs)
            if change.get("application_name") == application_name
        ],
        "review_tasks": [
            task
            for task in list_review_tasks(**scope_kwargs)
            if task.get("application_name") == application_name
        ],
        "deployments": [
            deployment
            for deployment in list_deployments(**scope_kwargs)
            if deployment.get("application_name") == application_name
        ],
        "deployment_gates": [
            gate
            for gate in list_deployment_gates(**scope_kwargs)
            if gate.get("application_name") == application_name
        ],
        "prompt_templates": [
            prompt
            for prompt in list_prompt_templates(**scope_kwargs)
            if prompt.get("application_name") == application_name
        ],
        "prompt_versions": [
            prompt
            for prompt in list_prompt_versions(**scope_kwargs)
            if prompt.get("application_name") == application_name
        ],
        "incidents": [
            incident
            for incident in list_incidents(**scope_kwargs)
            if incident.get("application_name") == application_name
        ],
        "owners": [
            owner
            for owner in list_owner_assignments(**scope_kwargs)
            if owner.get("application_name") == application_name
        ],
        "decisions": [
            decision
            for decision in list_decisions(**scope_kwargs)
            if decision.get("application_name") == application_name
        ],
        "exceptions": [
            exception
            for exception in list_exceptions(**scope_kwargs)
            if exception.get("application_name") == application_name
        ],
        "traces": build_trace_summaries(related_events),
        "recent_events": [event.model_dump() for event in related_events[-50:]],
        "trace_ids": trace_ids,
    }


def build_workflow_detail(scope: ScopeFilter, workflow_id: str) -> dict[str, Any] | None:
    scope_kwargs = scope.model_dump()
    workflows = list_workflows(**scope_kwargs)
    workflow = find_record(workflows, "entity_id", workflow_id)
    if workflow is None:
        return None

    workflow_name = workflow["workflow_name"]
    related_events = events_for_workflow(scope, workflow_name)
    return {
        "workflow": workflow,
        "applications": [
            application
            for application in list_applications(**scope_kwargs)
            if application["application_name"] in workflow.get("applications", [])
        ],
        "model_calls": [event.model_dump() for event in related_events if event.type == "model.call"],
        "agents": filter_by_workflow(build_agents(scope)["agents"], workflow_name),
        "retrievals": filter_by_workflow(build_retrievals(scope)["retrievals"], workflow_name),
        "tools": filter_by_workflow(build_tools(scope)["tools"], workflow_name),
        "guardrails": filter_by_workflow(build_guardrails(scope)["guardrails"], workflow_name),
        "evals": filter_by_workflow(build_evals(scope)["evals"], workflow_name),
        "risks": filter_by_workflow(list_risk_findings(**scope_kwargs), workflow_name),
        "controls": filter_by_workflow(list_control_assessments(**scope_kwargs), workflow_name),
        "deployments": filter_by_workflow(list_deployments(**scope_kwargs), workflow_name),
        "deployment_gates": filter_by_workflow(list_deployment_gates(**scope_kwargs), workflow_name),
        "prompt_templates": filter_by_workflow(list_prompt_templates(**scope_kwargs), workflow_name),
        "prompt_versions": filter_by_workflow(list_prompt_versions(**scope_kwargs), workflow_name),
        "incidents": filter_by_workflow(list_incidents(**scope_kwargs), workflow_name),
        "review_tasks": filter_by_workflow(list_review_tasks(**scope_kwargs), workflow_name),
        "traces": build_trace_summaries(related_events),
        "recent_events": [event.model_dump() for event in related_events[-50:]],
    }


def build_review_detail(scope: ScopeFilter, task_id: str) -> dict[str, Any] | None:
    scope_kwargs = scope.model_dump()
    task = find_record(list_review_tasks(**scope_kwargs), "task_id", task_id)
    if task is None:
        return None
    change = find_record(list_change_events(**scope_kwargs), "change_id", task.get("change_id"))
    return {
        "review_task": task,
        "change_event": change,
        "owners": [
            owner
            for owner in list_owner_assignments(**scope_kwargs)
            if owner.get("application_name") == task.get("application_name")
        ],
        "decisions": [
            decision
            for decision in list_decisions(**scope_kwargs)
            if decision.get("target_type") == "review_task" and decision.get("target_id") == task_id
        ],
        "exceptions": [
            exception
            for exception in list_exceptions(**scope_kwargs)
            if exception.get("application_name") == task.get("application_name")
        ],
    }


def build_deployment_gate_detail(scope: ScopeFilter, gate_id: str) -> dict[str, Any] | None:
    scope_kwargs = scope.model_dump()
    gate = find_record(list_deployment_gates(**scope_kwargs), "gate_id", gate_id)
    if gate is None:
        return None
    return {
        "deployment_gate": gate,
        "deployment": find_record(list_deployments(**scope_kwargs), "deployment_id", gate.get("deployment_id")),
        "deployment_version": find_record(list_deployment_versions(**scope_kwargs), "version_id", gate.get("version_id")),
        "prompt_version": find_record(list_prompt_versions(**scope_kwargs), "prompt_version_id", gate.get("prompt_version_id")),
        "risks": [
            risk
            for risk in list_risk_findings(**scope_kwargs)
            if risk.get("application_name") == gate.get("application_name")
        ],
        "controls": [
            control
            for control in list_control_assessments(**scope_kwargs)
            if control.get("application_name") == gate.get("application_name")
        ],
        "review_tasks": [
            task
            for task in list_review_tasks(**scope_kwargs)
            if task.get("application_name") == gate.get("application_name")
        ],
        "decisions": [
            decision
            for decision in list_decisions(**scope_kwargs)
            if decision.get("target_type") == "deployment_gate" and decision.get("target_id") == gate_id
        ],
        "exceptions": [
            exception
            for exception in list_exceptions(**scope_kwargs)
            if exception.get("application_name") == gate.get("application_name")
        ],
    }


def build_incident_detail(scope: ScopeFilter, incident_id: str) -> dict[str, Any] | None:
    scope_kwargs = scope.model_dump()
    incident = find_record(list_incidents(**scope_kwargs), "incident_id", incident_id)
    if incident is None:
        return None
    trace_id = incident.get("impacted_trace_id") or incident.get("trace_id")
    return {
        "incident": incident,
        "trace": build_trace_detail(scope, trace_id) if trace_id else None,
        "risks": [
            risk
            for risk in list_risk_findings(**scope_kwargs)
            if risk.get("application_name") == incident.get("application_name")
        ],
        "controls": [
            control
            for control in list_control_assessments(**scope_kwargs)
            if control.get("application_name") == incident.get("application_name")
        ],
        "deployment": find_record(list_deployments(**scope_kwargs), "deployment_id", incident.get("deployment_id")),
        "deployment_gate": find_record(list_deployment_gates(**scope_kwargs), "gate_id", incident.get("deployment_gate_id")),
        "owners": [
            owner
            for owner in list_owner_assignments(**scope_kwargs)
            if owner.get("subject_type") == "incident" and owner.get("subject_name") == incident_id
        ],
        "decisions": [
            decision
            for decision in list_decisions(**scope_kwargs)
            if decision.get("target_type") == "incident" and decision.get("target_id") == incident_id
        ],
    }


def build_trace_detail(scope: ScopeFilter, trace_id: str) -> dict[str, Any] | None:
    events = [event for event in scoped_events(scope) if event.trace_id == trace_id]
    if not events:
        return None
    return {
        "trace_id": trace_id,
        "status": "error" if any(event.status == "error" for event in events) else "success",
        "event_count": len(events),
        "started_at": events[0].timestamp,
        "ended_at": events[-1].timestamp,
        "application_name": event_metadata(events[0]).get("application_name"),
        "workflow_name": event_metadata(events[0]).get("workflow_name"),
        "events": [event.model_dump() for event in events],
        "spans": [
            {
                "span_id": event.span_id,
                "parent_span_id": event.parent_span_id,
                "type": event.type,
                "name": event.name,
                "status": event.status,
                "timestamp": event.timestamp,
                "duration_ms": event.duration_ms,
                "attributes": event.attributes,
            }
            for event in events
        ],
    }


def events_for_application(scope: ScopeFilter, application_name: str) -> list[Event]:
    return [
        event
        for event in scoped_events(scope)
        if event_metadata(event).get("application_name") == application_name
    ]


def events_for_workflow(scope: ScopeFilter, workflow_name: str) -> list[Event]:
    return [
        event
        for event in scoped_events(scope)
        if event_metadata(event).get("workflow_name") == workflow_name or event.name == workflow_name
    ]


def filter_by_workflow(rows: list[dict[str, Any]], workflow_name: str) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("workflow_name") == workflow_name]


def build_trace_summaries(events: list[Event]) -> list[dict[str, Any]]:
    trace_counts = Counter(event.trace_id for event in events)
    return [
        {
            "trace_id": trace_id,
            "event_count": count,
            "status": "error" if any(event.status == "error" and event.trace_id == trace_id for event in events) else "success",
        }
        for trace_id, count in trace_counts.most_common(50)
    ]


def find_record(rows: list[dict[str, Any]], key: str, value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return next((row for row in rows if row.get(key) == value), None)


def build_risk_register(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"risks": list_risk_findings(**scope.model_dump())}


def build_control_catalog(tenant_id: str | None = None) -> dict[str, list[dict[str, Any]]]:
    return {"controls": list_controls_catalog(tenant_id)}


def build_risk_rules(tenant_id: str | None = None) -> dict[str, list[dict[str, Any]]]:
    return {"risk_rules": list_configured_risk_rules(tenant_id)}


def build_owner_policies() -> dict[str, list[dict[str, Any]]]:
    return {"owner_policies": list_configured_owner_policies()}


def build_platform_users(tenant_id: str | None = None) -> dict[str, list[dict[str, Any]]]:
    return {"users": list_platform_users(tenant_id=tenant_id)}


def build_role_assignments(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"role_assignments": list_role_assignments(**scope.model_dump())}


def build_review_queue_policies() -> dict[str, list[dict[str, Any]]]:
    return {"review_queue_policies": list_review_queue_policies()}


def build_deployments(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"deployments": list_deployments(**scope.model_dump())}


def build_deployment_versions(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"deployment_versions": list_deployment_versions(**scope.model_dump())}


def build_deployment_gates(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"deployment_gates": list_deployment_gates(**scope.model_dump())}


def build_prompt_templates(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"prompt_templates": list_prompt_templates(**scope.model_dump())}


def build_prompt_versions(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"prompt_versions": list_prompt_versions(**scope.model_dump())}


def build_incidents(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"incidents": list_incidents(**scope.model_dump())}


def build_control_evidence(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"controls": list_control_assessments(**scope.model_dump())}


# Prefixes used in control framework_refs, mapped to a display family. A control
# assessment cites specific requirements (e.g. "NIST AI RMF MAP 1.1",
# "ISO/IEC 42001 A.5.2", "EU AI Act Art 26", "SOC 2 CC7.2"); we roll these up per
# framework so a buyer/auditor sees coverage by regulation, not a flat list
# (audit §6.2, GTM: framework crosswalks are table-stakes).
_FRAMEWORK_FAMILIES: list[tuple[str, str]] = [
    ("OWASP Agentic", "OWASP Top 10 for Agentic Applications (2026)"),
    ("NIST AI 600", "NIST GenAI Profile (AI 600-1)"),
    ("NIST AI RMF", "NIST AI RMF"),
    ("ISO/IEC 42001", "ISO/IEC 42001"),
    ("ISO/IEC 23894", "ISO/IEC 23894"),
    ("EU AI Act", "EU AI Act"),
    ("SOC 2", "SOC 2"),
]

_SATISFIED_STATUSES = {"passing", "waived"}


def _framework_family(ref: str) -> str:
    for prefix, name in _FRAMEWORK_FAMILIES:
        if ref.startswith(prefix) or prefix in ref:
            return name
    return "Other"


def build_framework_coverage(scope: ScopeFilter) -> dict[str, Any]:
    """Roll control assessments up into per-framework coverage.

    The denominator is every requirement the Norinth control library *maps* for a
    framework, taken from the control definitions — not only the requirements
    that happen to have produced an assessment. Otherwise a single passing
    control reported 100% coverage of its whole framework (audit finding H8). A
    requirement counts as satisfied when a control that cites it has a passing or
    waived assessment; a mapped requirement with no satisfying assessment is a
    gap. ``basis`` states plainly that this is coverage of the controls Norinth
    maps, not of the full regulation.
    """
    # Denominator: every framework requirement the control library defines.
    by_family: dict[str, dict[str, bool]] = {}
    for control in list_controls_catalog(scope.tenant_id):
        for ref in control.get("framework_refs", []):
            family = _framework_family(ref)
            by_family.setdefault(family, {}).setdefault(ref, False)

    # Numerator: requirements whose citing control has a satisfying assessment.
    for assessment in list_control_assessments(**scope.model_dump()):
        satisfied = assessment.get("status") in _SATISFIED_STATUSES
        if not satisfied:
            continue
        for ref in assessment.get("framework_refs", []):
            family = _framework_family(ref)
            requirements = by_family.setdefault(family, {})
            requirements[ref] = True

    coverage: list[dict[str, Any]] = []
    for family, requirements in by_family.items():
        total = len(requirements)
        satisfied_count = sum(1 for ok in requirements.values() if ok)
        coverage.append(
            {
                "framework": family,
                "total_requirements": total,
                "satisfied": satisfied_count,
                "coverage_pct": round(100 * satisfied_count / total) if total else 0,
                "gaps": sorted(ref for ref, ok in requirements.items() if not ok),
                "satisfied_requirements": sorted(ref for ref, ok in requirements.items() if ok),
            }
        )
    return {
        "framework_coverage": sorted(coverage, key=lambda item: item["framework"]),
        "basis": "Coverage of the control requirements the Norinth control library maps for each framework, not of the full regulation.",
    }


def build_change_events(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"changes": list_change_events(**scope.model_dump())}


def build_review_tasks(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"review_tasks": list_review_tasks(**scope.model_dump())}


def build_owner_assignments(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"owners": list_owner_assignments(**scope.model_dump())}


def build_decisions(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"decisions": list_decisions(**scope.model_dump())}


def build_exceptions(scope: ScopeFilter) -> dict[str, list[dict[str, Any]]]:
    return {"exceptions": list_exceptions(**scope.model_dump())}


def build_traces_page(scope: ScopeFilter, *, limit: int, offset: int) -> dict[str, Any]:
    """Trace list paged and counted in SQL (H9): the whole event table is never
    loaded just to count events per trace and slice the result in Python."""
    traces, total = aggregate_traces(**scope.model_dump(), limit=limit, offset=offset)
    return {
        "traces": traces,
        "page": {
            "offset": offset,
            "limit": limit,
            "total": total,
            "has_more": offset + len(traces) < total,
        },
    }


def build_summary(scope: ScopeFilter) -> dict[str, Any]:
    # Event counts are computed in SQL, not by materialising a 10,000-row window
    # and counting in Python, so they stay correct past that size (H9).
    scope_filters = scope.model_dump()
    by_type = count_events_by_type(**scope_filters)
    total_events = sum(by_type.values())
    error_events = count_error_events(**scope_filters)
    distinct_systems = count_distinct("COALESCE(system, service)", **scope_filters)
    applications = list_applications(**scope.model_dump())
    workflows = list_workflows(**scope.model_dump())
    providers = list_providers(**scope.model_dump())
    controls = list_control_assessments(**scope.model_dump())
    risks = list_risk_findings(**scope.model_dump())
    changes = list_change_events(**scope.model_dump())
    review_tasks = list_review_tasks(**scope.model_dump())
    deployment_gates = list_deployment_gates(**scope.model_dump())
    prompt_templates = list_prompt_templates(**scope.model_dump())
    prompt_versions = list_prompt_versions(**scope.model_dump())
    incidents = list_incidents(**scope.model_dump())
    owners = list_owner_assignments(**scope.model_dump())
    decisions = list_decisions(**scope.model_dump())
    exceptions = list_exceptions(**scope.model_dump())
    return {
        "events": total_events,
        "model_calls": by_type.get("model.call", 0),
        "agent_runs": by_type.get("agent.run", 0),
        "retrievals": by_type.get("retrieval.call", 0),
        "tool_calls": by_type.get("tool.call", 0),
        "guardrail_decisions": by_type.get("guardrail.decision", 0),
        "eval_results": by_type.get("eval.result", 0),
        "prompt_events": by_type.get("prompt.event", 0),
        "deployment_events": by_type.get("deployment.event", 0),
        "incident_events": by_type.get("incident.event", 0),
        "errors": error_events,
        "systems": distinct_systems,
        "applications": len(applications),
        "workflows": len(workflows),
        "providers": sorted({provider["provider"] for provider in providers}),
        "control_assessments": len(controls),
        "passing_controls": sum(1 for control in controls if control["status"] == "passing"),
        "risk_findings": len(risks),
        "material_changes": len(changes),
        "open_reviews": sum(1 for task in review_tasks if task["status"] == "open"),
        "deployment_gates": len(deployment_gates),
        "prompt_templates": len(prompt_templates),
        "prompt_versions": len(prompt_versions),
        "prompt_ready_gates": sum(1 for gate in deployment_gates if gate.get("prompt_evidence_status") == "linked" and int(gate.get("passing_eval_count") or 0) > 0),
        "pending_deployment_gates": sum(1 for gate in deployment_gates if gate["gate_status"] == "pending_review"),
        "blocked_deployments": sum(1 for gate in deployment_gates if gate["gate_status"] == "rejected"),
        "open_incidents": sum(1 for incident in incidents if incident["status"] != "closed"),
        "critical_incidents": sum(1 for incident in incidents if incident["severity"].lower() in {"critical", "high"} and incident["status"] != "closed"),
        "overdue_reviews": sum(1 for task in review_tasks if task.get("escalation_status") in {"overdue", "escalated"}),
        "escalated_reviews": sum(1 for task in review_tasks if task.get("escalation_status") == "escalated"),
        "unassigned_owners": sum(1 for owner in owners if owner["status"] == "unassigned"),
        "decisions": len(decisions),
        "active_exceptions": sum(1 for exception in exceptions if exception["status"] == "active"),
    }

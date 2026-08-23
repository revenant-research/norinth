from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.pagination import PageParams, paginate
from app.dependencies import ActorContext, current_actor, now, scoped_dependency
from app.schemas.events import ScopeFilter
from app.schemas.workflow import (
    ControlDefinitionRequest,
    DecisionRequest,
    DeploymentGateDecisionRequest,
    ExceptionRequest,
    OwnerAssignmentRequest,
    OwnerPolicyRequest,
    ReviewQueuePolicyRequest,
    RiskRuleRequest,
)
from app.services.authorization import (
    AuthorizationError,
    require_config_write,
    require_decision,
    require_exception,
    require_owner_assignment,
)
from app.services.governance import (
    build_agents,
    build_application_detail,
    build_applications,
    build_change_events,
    build_control_catalog,
    build_control_evidence,
    build_decisions,
    build_deployment_gate_detail,
    build_deployment_gates,
    build_deployment_versions,
    build_deployments,
    build_evals,
    build_exceptions,
    build_guardrails,
    build_incident_detail,
    build_incidents,
    build_models,
    build_owner_assignments,
    build_owner_policies,
    build_prompt_templates,
    build_prompt_versions,
    build_resource_graph,
    build_resource_graph_neighborhood,
    build_retrievals,
    build_review_detail,
    build_review_queue_policies,
    build_review_tasks,
    build_risk_register,
    build_risk_rules,
    build_summary,
    build_systems,
    build_tools,
    build_trace_detail,
    build_traces,
    build_workflow_detail,
    build_workflows,
)
from app.services.notifications import emit as notify
from app.services.notifications import public_base_url
from app.storage.audit import record_audit
from app.storage.deployments import load_deployment_gate, set_deployment_gate_status
from app.storage.governance_policy import upsert_control_definition, upsert_risk_rule
from app.storage.incidents import load_incident, set_incident_status
from app.storage.intake import intake_submitter
from app.storage.raw_events import connect, count_events, count_scoped_events, list_events, list_scopes
from app.storage.workflow import (
    assign_owner,
    create_exception,
    load_decision_target,
    load_owner_assignment,
    record_decision,
    upsert_owner_policy,
    upsert_review_queue_policy,
)

router = APIRouter()


def raise_forbidden(error: AuthorizationError) -> None:
    raise HTTPException(status_code=403, detail=str(error))


def enforce_segregation_of_duties(actor: ActorContext, target_type: str, target: dict) -> None:
    """Maker-checker control: a user may not approve work they themselves
    originated. The check is applied where the originating user is recorded;
    intake-originated review tasks resolve the submitter from the use case."""
    maker: str | None = None
    if target_type == "review_task" and target.get("task_type") == "intake_review":
        maker = intake_submitter(target.get("change_id", ""))
    else:
        maker = target.get("submitted_by") or target.get("created_by")
    if maker and maker == actor.user_ref:
        raise HTTPException(
            status_code=403,
            detail="Segregation of duties: a user cannot record a decision on work they originated",
        )


@router.get("/health")
def health():
    return {"ok": True, "time": now(), "event_count": count_events()}


@router.get("/api/scopes")
def scopes(actor: ActorContext = Depends(current_actor)):
    # The platform super admin works on organizations, not tenant data scopes.
    if actor.is_super_admin:
        return {"tenants": [], "projects": [], "environments": []}
    available = list_scopes()
    # Tenant actors only ever see their own organization's scope.
    return {
        "tenants": [actor.tenant_id] if actor.tenant_id else [],
        "projects": available["projects"],
        "environments": available["environments"],
    }


def _event_page(scope: ScopeFilter, page: PageParams, key: str, event_type: str | None = None) -> dict:
    """SQL-level window over sdk_events (never materialises the whole table)."""
    filters = scope.model_dump()
    items = list_events(**filters, event_type=event_type, limit=page.limit, offset=page.offset)
    total = count_scoped_events(**filters, event_type=event_type)
    return {
        key: items,
        "page": {
            "offset": page.offset,
            "limit": page.limit,
            "total": total,
            "has_more": page.offset + len(items) < total,
        },
    }


@router.get("/api/events")
def events(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return _event_page(scope, page, "events")


@router.get("/api/systems")
def systems(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_systems(scope)


@router.get("/api/applications")
def applications(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_applications(scope)


@router.get("/api/applications/{application_id}")
def application_detail(application_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_application_detail(scope, application_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return detail


@router.get("/api/workflows")
def workflows(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_workflows(scope)


@router.get("/api/workflows/{workflow_id}")
def workflow_detail(workflow_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_workflow_detail(scope, workflow_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return detail


@router.get("/api/models")
def models(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_models(scope)


@router.get("/api/resource-graph")
def resource_graph(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_resource_graph(scope)


@router.get("/api/resource-graph/neighborhood")
def resource_graph_neighborhood(node_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    return build_resource_graph_neighborhood(scope, node_id)


@router.get("/api/retrievals")
def retrievals(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_retrievals(scope), "retrievals", page)


@router.get("/api/tools")
def tools(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_tools(scope), "tools", page)


@router.get("/api/guardrails")
def guardrails(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_guardrails(scope), "guardrails", page)


@router.get("/api/evals")
def evals(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_evals(scope), "evals", page)


@router.get("/api/agents")
def agents(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_agents(scope), "agents", page)


@router.get("/api/risk-register")
def risk_register(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_risk_register(scope), "risks", page)


@router.get("/api/control-evidence")
def control_evidence(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_control_evidence(scope), "controls", page)


@router.get("/api/control-catalog")
def control_catalog(actor: ActorContext = Depends(current_actor)):
    return build_control_catalog()


@router.post("/api/control-catalog")
def configure_control(payload: ControlDefinitionRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    return {"control": upsert_control_definition(payload.model_dump())}


@router.get("/api/risk-rules")
def risk_rules(actor: ActorContext = Depends(current_actor)):
    return build_risk_rules()


@router.post("/api/risk-rules")
def configure_risk_rule(payload: RiskRuleRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    return {"risk_rule": upsert_risk_rule(payload.model_dump())}


@router.get("/api/owner-policies")
def owner_policies(actor: ActorContext = Depends(current_actor)):
    return build_owner_policies()


@router.post("/api/owner-policies")
def configure_owner_policy(payload: OwnerPolicyRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    return {"owner_policy": upsert_owner_policy(payload.model_dump())}


# NOTE: user and role-assignment management is intentionally NOT exposed on this
# tenant-governance router. It lives only on the org-administration plane
# (`/api/org/users`, `/api/org/role-assignments` in api/admin.py), which enforces
# tenant scoping, role allow-lists, and separation of duties. The previous
# `POST /api/users` / `POST /api/role-assignments` endpoints here were removed:
# they authorized on `config.write` with no tenant scoping on the target, which
# let any config.write holder overwrite arbitrary accounts (including the super
# admin — a lockout DoS) and self-grant globally-scoped roles (H-2).


@router.get("/api/review-queue-policies")
def review_queue_policies(actor: ActorContext = Depends(current_actor)):
    return build_review_queue_policies()


@router.post("/api/review-queue-policies")
def configure_review_queue_policy(payload: ReviewQueuePolicyRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    return {"review_queue_policy": upsert_review_queue_policy(payload.model_dump())}


@router.get("/api/change-events")
def change_events(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_change_events(scope), "changes", page)


@router.get("/api/review-tasks")
def review_tasks(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_review_tasks(scope), "review_tasks", page)


@router.get("/api/reviews/{task_id}")
def review_detail(task_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_review_detail(scope, task_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Review task not found")
    return detail


@router.get("/api/deployments")
def deployments(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_deployments(scope)


@router.get("/api/deployment-versions")
def deployment_versions(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_deployment_versions(scope)


@router.get("/api/deployment-gates")
def deployment_gates(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_deployment_gates(scope), "deployment_gates", page)


@router.get("/api/deployment-gates/{gate_id}")
def deployment_gate_detail(gate_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_deployment_gate_detail(scope, gate_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Deployment gate not found")
    return detail


@router.get("/api/prompt-templates")
def prompt_templates(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_prompt_templates(scope)


@router.get("/api/prompt-versions")
def prompt_versions(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_prompt_versions(scope)


@router.get("/api/incidents")
def incidents(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_incidents(scope), "incidents", page)


@router.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_incident_detail(scope, incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return detail


@router.post("/api/incidents/{incident_id}/close")
def close_incident(incident_id: str, payload: DeploymentGateDecisionRequest, actor: ActorContext = Depends(current_actor)):
    incident = load_incident(incident_id)
    incident["target_type"] = "incident"
    try:
        require_decision(actor, incident)
    except AuthorizationError as error:
        raise_forbidden(error)
    enforce_segregation_of_duties(actor, "incident", incident)
    updated_incident = set_incident_status(incident_id, "closed", actor.user_ref, payload.rationale)
    decision = record_decision("incident", incident_id, "close", payload.rationale, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="incident.close", tenant_id=incident.get("tenant_id"), target_type="incident", target_id=incident_id)
    with connect() as connection:
        notify(
            connection,
            tenant_id=incident.get("tenant_id"),
            event_type="incident.closed",
            subject=f"Incident closed: {incident.get('title') or incident_id}",
            text=f"{actor.user_ref} closed the incident for {incident.get('application_name')} / {incident.get('workflow_name')}.\n\nRationale: {payload.rationale}",
            data={"incident_id": incident_id, "application_name": incident.get("application_name"), "severity": incident.get("severity"), "closed_by": actor.user_ref},
            to_roles=["org_admin", "risk_owner"],
            link=f"{public_base_url()}/#incident/{incident_id}",
        )
    return {"incident": updated_incident, "decision": decision}


@router.post("/api/deployment-gates/{gate_id}/approve")
def approve_deployment_gate(gate_id: str, payload: DeploymentGateDecisionRequest, actor: ActorContext = Depends(current_actor)):
    gate = load_deployment_gate(gate_id)
    gate["target_type"] = "deployment_gate"
    try:
        require_decision(actor, gate)
    except AuthorizationError as error:
        raise_forbidden(error)
    enforce_segregation_of_duties(actor, "deployment_gate", gate)
    try:
        updated_gate = set_deployment_gate_status(gate_id, "approved", actor.user_ref, payload.rationale)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    decision = record_decision("deployment_gate", gate_id, "approve", payload.rationale, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="gate.approve", tenant_id=gate.get("tenant_id"), target_type="deployment_gate", target_id=gate_id)
    with connect() as connection:
        notify(
            connection,
            tenant_id=gate.get("tenant_id"),
            event_type="gate.approved",
            subject=f"Release gate approved: {gate.get('application_name')} / {gate.get('workflow_name')}",
            text=f"{actor.user_ref} approved the release gate for {gate.get('application_name')} / {gate.get('workflow_name')}.\n\nRationale: {payload.rationale}",
            data={"gate_id": gate_id, "application_name": gate.get("application_name"), "workflow_name": gate.get("workflow_name"), "decided_by": actor.user_ref},
            to_users=[u for u in [gate.get("submitted_by"), gate.get("created_by")] if u],
            to_roles=["org_admin"],
            link=f"{public_base_url()}/#gate/{gate_id}",
        )
    return {"deployment_gate": updated_gate, "decision": decision}


@router.post("/api/deployment-gates/{gate_id}/reject")
def reject_deployment_gate(gate_id: str, payload: DeploymentGateDecisionRequest, actor: ActorContext = Depends(current_actor)):
    gate = load_deployment_gate(gate_id)
    gate["target_type"] = "deployment_gate"
    try:
        require_decision(actor, gate)
    except AuthorizationError as error:
        raise_forbidden(error)
    enforce_segregation_of_duties(actor, "deployment_gate", gate)
    updated_gate = set_deployment_gate_status(gate_id, "rejected", actor.user_ref, payload.rationale)
    decision = record_decision("deployment_gate", gate_id, "reject", payload.rationale, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="gate.reject", tenant_id=gate.get("tenant_id"), target_type="deployment_gate", target_id=gate_id)
    with connect() as connection:
        notify(
            connection,
            tenant_id=gate.get("tenant_id"),
            event_type="gate.rejected",
            subject=f"Release gate rejected: {gate.get('application_name')} / {gate.get('workflow_name')}",
            text=f"{actor.user_ref} rejected the release gate for {gate.get('application_name')} / {gate.get('workflow_name')}.\n\nRationale: {payload.rationale}",
            data={"gate_id": gate_id, "application_name": gate.get("application_name"), "workflow_name": gate.get("workflow_name"), "decided_by": actor.user_ref},
            to_users=[u for u in [gate.get("submitted_by"), gate.get("created_by")] if u],
            to_roles=["org_admin"],
            link=f"{public_base_url()}/#gate/{gate_id}",
        )
    return {"deployment_gate": updated_gate, "decision": decision}


@router.get("/api/owner-assignments")
def owner_assignments(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_owner_assignments(scope), "owners", page)


@router.post("/api/owner-assignments/{owner_assignment_id}/assign")
def assign_owner_route(owner_assignment_id: str, payload: OwnerAssignmentRequest, actor: ActorContext = Depends(current_actor)):
    assignment = load_owner_assignment(owner_assignment_id)
    try:
        require_owner_assignment(actor, assignment)
    except AuthorizationError as error:
        raise_forbidden(error)
    result = assign_owner(owner_assignment_id, payload.owner_ref, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="owner.assign", tenant_id=assignment.get("tenant_id"), target_type="owner_assignment", target_id=owner_assignment_id, detail={"owner_ref": payload.owner_ref})
    return {"owner_assignment": result}


@router.get("/api/decisions")
def decisions(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_decisions(scope), "decisions", page)


# The only decisions the workflow understands. Anything else previously fell
# through and was written verbatim as the target's status, letting a reviewer
# escape the workflow by inventing a status string.
_ALLOWED_DECISIONS = {"approve", "reject", "accept_risk", "mitigate", "waive", "close"}


@router.post("/api/decisions")
def create_decision(payload: DecisionRequest, actor: ActorContext = Depends(current_actor)):
    if payload.decision not in _ALLOWED_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"decision must be one of {sorted(_ALLOWED_DECISIONS)}",
        )
    # Deployment gates and incidents have dedicated, guarded endpoints
    # (/approve, /reject, /close) that enforce evidence and attribution. They
    # must not be transitioned through the generic decision route, which would
    # bypass those guards.
    if payload.target_type in {"deployment_gate", "incident"}:
        raise HTTPException(
            status_code=400,
            detail=(
                "Use the dedicated endpoint for this target type: deployment gates via "
                "/api/deployment-gates/{id}/approve|reject, incidents via /api/incidents/{id}/close"
            ),
        )
    try:
        target = load_decision_target(payload.target_type, payload.target_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    target["target_type"] = payload.target_type
    try:
        require_decision(actor, target)
    except AuthorizationError as error:
        raise_forbidden(error)
    enforce_segregation_of_duties(actor, payload.target_type, target)
    decision = record_decision(payload.target_type, payload.target_id, payload.decision, payload.rationale, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="review.decide", tenant_id=target.get("tenant_id"), target_type=payload.target_type, target_id=payload.target_id, detail={"decision": payload.decision})
    return {"decision": decision}


@router.get("/api/exceptions")
def exceptions(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_exceptions(scope), "exceptions", page)


@router.post("/api/exceptions")
def create_exception_route(payload: ExceptionRequest, actor: ActorContext = Depends(current_actor)):
    target = load_decision_target(payload.target_type, payload.target_id)
    target["target_type"] = payload.target_type
    try:
        require_exception(actor, target)
    except AuthorizationError as error:
        raise_forbidden(error)
    exception = create_exception(
        payload.target_type,
        payload.target_id,
        payload.reason,
        payload.compensating_control,
        payload.expires_at,
        actor.user_ref,
    )
    record_audit(actor_ref=actor.user_ref, action="risk.accept", tenant_id=target.get("tenant_id"), target_type=payload.target_type, target_id=payload.target_id)
    return {"exception": exception}


@router.get("/api/sdk-health")
def sdk_health(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    # sdk.health events are stamped with the authenticated tenant at ingestion
    # (C-1), so they must be tenant-scoped like every other read; previously the
    # tenant filter was dropped, leaking other tenants' telemetry.
    return _event_page(scope, page, "sdk_health", event_type="sdk.health")


@router.get("/api/traces")
def traces(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_traces(scope), "traces", page)


@router.get("/api/traces/{trace_id}")
def trace_detail(trace_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_trace_detail(scope, trace_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return detail


@router.get("/api/model-calls")
def model_calls(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return _event_page(scope, page, "model_calls", event_type="model.call")


@router.get("/api/summary")
def summary(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_summary(scope)

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import ActorContext, current_actor, now, scoped_dependency
from app.schemas.events import ScopeFilter
from app.schemas.workflow import (
    ControlDefinitionRequest,
    DecisionRequest,
    DeploymentGateDecisionRequest,
    ExceptionRequest,
    OwnerAssignmentRequest,
    OwnerPolicyRequest,
    PlatformUserRequest,
    ReviewQueuePolicyRequest,
    RiskRuleRequest,
    RoleAssignmentRequest,
)
from app.services.governance import (
    build_agents,
    build_application_detail,
    build_applications,
    build_change_events,
    build_control_catalog,
    build_control_evidence,
    build_deployment_gate_detail,
    build_deployment_gates,
    build_deployment_versions,
    build_deployments,
    build_decisions,
    build_evals,
    build_exceptions,
    build_guardrails,
    build_incident_detail,
    build_incidents,
    build_models,
    build_owner_assignments,
    build_owner_policies,
    build_platform_users,
    build_prompt_templates,
    build_prompt_versions,
    build_retrievals,
    build_resource_graph,
    build_resource_graph_neighborhood,
    build_risk_register,
    build_risk_rules,
    build_review_detail,
    build_review_queue_policies,
    build_review_tasks,
    build_role_assignments,
    build_summary,
    build_systems,
    build_tools,
    build_trace_detail,
    build_traces,
    build_workflow_detail,
    build_workflows,
)
from app.services.authorization import (
    AuthorizationError,
    require_config_write,
    require_decision,
    require_exception,
    require_owner_assignment,
)
from app.storage.audit import record_audit
from app.storage.deployments import load_deployment_gate, set_deployment_gate_status
from app.storage.governance_policy import upsert_control_definition, upsert_risk_rule
from app.storage.incidents import load_incident, set_incident_status
from app.storage.intake import intake_submitter
from app.storage.raw_events import count_events, list_events, list_scopes
from app.storage.workflow import (
    assign_owner,
    create_exception,
    load_decision_target,
    load_owner_assignment,
    record_decision,
    upsert_owner_policy,
    upsert_platform_user,
    upsert_review_queue_policy,
    upsert_role_assignment,
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


@router.get("/api/events")
def events(scope: ScopeFilter = Depends(scoped_dependency)):
    return {"events": list_events(**scope.model_dump(), limit=200)}


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
def retrievals(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_retrievals(scope)


@router.get("/api/tools")
def tools(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_tools(scope)


@router.get("/api/guardrails")
def guardrails(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_guardrails(scope)


@router.get("/api/evals")
def evals(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_evals(scope)


@router.get("/api/agents")
def agents(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_agents(scope)


@router.get("/api/risk-register")
def risk_register(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_risk_register(scope)


@router.get("/api/control-evidence")
def control_evidence(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_control_evidence(scope)


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


@router.get("/api/users")
def users(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_platform_users(tenant_id=scope.tenant_id)


@router.post("/api/users")
def configure_user(payload: PlatformUserRequest, actor: ActorContext = Depends(current_actor)):
    user = payload.model_dump()
    try:
        require_config_write(actor, user)
    except AuthorizationError as error:
        raise_forbidden(error)
    return {"user": upsert_platform_user(user)}


@router.get("/api/role-assignments")
def role_assignments(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_role_assignments(scope)


@router.post("/api/role-assignments")
def configure_role_assignment(payload: RoleAssignmentRequest, actor: ActorContext = Depends(current_actor)):
    assignment = payload.model_dump()
    try:
        require_config_write(actor, assignment)
    except AuthorizationError as error:
        raise_forbidden(error)
    return {"role_assignment": upsert_role_assignment(assignment)}


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
def change_events(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_change_events(scope)


@router.get("/api/review-tasks")
def review_tasks(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_review_tasks(scope)


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
def deployment_gates(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_deployment_gates(scope)


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
def incidents(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_incidents(scope)


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
        raise HTTPException(status_code=400, detail=str(error))
    decision = record_decision("deployment_gate", gate_id, "approve", payload.rationale, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="gate.approve", tenant_id=gate.get("tenant_id"), target_type="deployment_gate", target_id=gate_id)
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
    return {"deployment_gate": updated_gate, "decision": decision}


@router.get("/api/owner-assignments")
def owner_assignments(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_owner_assignments(scope)


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
def decisions(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_decisions(scope)


@router.post("/api/decisions")
def create_decision(payload: DecisionRequest, actor: ActorContext = Depends(current_actor)):
    target = load_decision_target(payload.target_type, payload.target_id)
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
def exceptions(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_exceptions(scope)


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
def sdk_health(scope: ScopeFilter = Depends(scoped_dependency)):
    return {"sdk_health": list_events(project=scope.project, environment=scope.environment, event_type="sdk.health", limit=100)}


@router.get("/api/traces")
def traces(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_traces(scope)


@router.get("/api/traces/{trace_id}")
def trace_detail(trace_id: str, scope: ScopeFilter = Depends(scoped_dependency)):
    detail = build_trace_detail(scope, trace_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Trace not found")
    return detail


@router.get("/api/model-calls")
def model_calls(scope: ScopeFilter = Depends(scoped_dependency)):
    return {"model_calls": list_events(**scope.model_dump(), event_type="model.call", limit=100)}


@router.get("/api/summary")
def summary(scope: ScopeFilter = Depends(scoped_dependency)):
    return build_summary(scope)

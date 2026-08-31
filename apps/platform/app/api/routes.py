# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response

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
    RetentionPolicyRequest,
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
    build_traces_page,
    build_workflow_detail,
    build_workflows,
)
from app.services.notifications import emit as notify
from app.services.notifications import public_base_url
from app.storage.audit import record_audit
from app.storage.deployments import (
    gate_deployer,
    load_deployment_gate,
    refresh_deployment_gates,
    set_deployment_gate_status,
)
from app.storage.errors import RecordNotFound
from app.storage.governance_policy import upsert_control_definition, upsert_risk_rule
from app.storage.incidents import load_incident, set_incident_status
from app.storage.intake import intake_submitter
from app.storage.raw_events import connect, count_scoped_events, list_events, list_scopes
from app.storage.retention import MIN_RETENTION_DAYS, retention_days_for, set_retention_days
from app.storage.workflow import (
    assign_owner,
    create_exception,
    expire_due_exceptions,
    load_decision_target,
    load_owner_assignment,
    record_decision,
    upsert_owner_policy,
    upsert_review_queue_policy,
)

router = APIRouter()


def raise_forbidden(error: AuthorizationError) -> None:
    raise HTTPException(status_code=403, detail=str(error))


def _require_tenant_for_config(actor: ActorContext) -> str:
    """config writes are per-org; super admin has no tenant to scope to"""
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Configuration changes are made within an organization")
    return actor.tenant_id


def enforce_segregation_of_duties(actor: ActorContext, target_type: str, target: dict) -> None:
    """maker-checker: a user can't approve work they originated"""
    maker: str | None = None
    if target_type == "review_task" and target.get("task_type") in {"intake_review", "recertification_review"}:
        maker = intake_submitter(target.get("change_id", ""))
    elif target_type == "deployment_gate":
        # deployer can't approve its own release
        maker = gate_deployer(target.get("version_id", ""))
    elif target_type == "incident":
        maker = target.get("detected_by")
    else:
        maker = target.get("submitted_by") or target.get("created_by")
    if maker and maker == actor.user_ref:
        raise HTTPException(
            status_code=403,
            detail="Segregation of duties: a user cannot record a decision on work they originated",
        )


def enforce_stage_policy(actor: ActorContext, target_type: str, target: dict, decision: str) -> None:
    """route staged approvals through the stage machinery

    a review task whose governing policy declared several stages cannot be
    approved or rejected in one direct decision: each stage is decided by a
    different person via /api/approval-stages/{id}/decide. a single-stage task
    keeps this route's pre-policy wire behavior, with the stage's role
    authority checked here so the policy's chosen role is enforced
    """
    if target_type != "review_task" or decision not in {"approve", "reject"}:
        return
    from app.services.authorization import require_stage_role
    from app.storage.policy_engine import stages_for_subject

    stages = stages_for_subject("review_task", target.get("task_id", ""), 0)
    if not stages:
        return
    undecided = [stage for stage in stages if stage["status"] in {"open", "pending"}]
    if len(stages) > 1:
        raise HTTPException(
            status_code=400,
            detail=(
                "This review is governed by a multi-stage approval policy "
                f"(policy {stages[0]['policy_tenant'] or 'default'}/v{stages[0]['policy_version']}). "
                "Decide its open stage via /api/approval-stages/{stage_id}/decide instead."
            ),
        )
    if undecided:
        try:
            require_stage_role(actor, stages[0]["required_role"], {
                "tenant_id": target.get("tenant_id"),
                "project": target.get("project"),
                "environment": target.get("environment"),
            })
        except AuthorizationError as error:
            raise_forbidden(error)


@router.get("/health")
def health():
    # liveness probe, no db count (would table-scan and leak totals)
    return {"ok": True, "time": now()}


@router.get("/health/ready")
def health_ready(response: Response):
    """readiness probe: the process is only ready if its database answers

    liveness deliberately skips the db (a db outage should not make the
    orchestrator kill and churn pods), but readiness must include it — a pod
    that cannot reach its database serves nothing but errors, and reporting
    Ready kept it in the load balancer. SELECT 1: no table scan, no totals
    """
    try:
        with connect() as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception:
        response.status_code = 503
        return {"ok": False, "database": "unreachable", "time": now()}
    return {"ok": True, "database": "ok", "time": now()}


@router.get("/api/scopes")
def scopes(actor: ActorContext = Depends(current_actor)):
    # super admin works on orgs, not tenant scopes; a user with no org has no
    # scopes. neither may see another tenant's project/environment names
    if actor.is_super_admin or not actor.tenant_id:
        return {"tenants": [], "projects": [], "environments": []}
    available = list_scopes(actor.tenant_id)
    return {
        "tenants": [actor.tenant_id],
        "projects": available["projects"],
        "environments": available["environments"],
    }


def _event_page(scope: ScopeFilter, page: PageParams, key: str, event_type: str | None = None) -> dict:
    """sql-level window over sdk_events"""
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
def events(
    actor: ActorContext = Depends(current_actor),
    scope: ScopeFilter = Depends(scoped_dependency),
    page: PageParams = Depends(),
):
    result = _event_page(scope, page, "events")
    # the events view returns record-level raw bodies (including captured
    # content where an org opted in), so reading it is an access event:
    # "who viewed this record" must have an answer. aggregate dashboards
    # derived from the same data stay unaudited by design
    record_audit(
        actor_ref=actor.user_ref,
        action="access.events",
        tenant_id=scope.tenant_id,
        detail={
            "project": scope.project,
            "environment": scope.environment,
            "offset": page.offset,
            "limit": page.limit,
            "returned": len(result["events"]),
        },
    )
    return result


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
    # a lapsed exception reopens the finding it waived; without this the register
    # keeps reporting it as accepted until the next batch of telemetry
    expire_due_exceptions()
    return paginate(build_risk_register(scope), "risks", page)


@router.get("/api/control-evidence")
def control_evidence(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return paginate(build_control_evidence(scope), "controls", page)


@router.get("/api/control-catalog")
def control_catalog(actor: ActorContext = Depends(current_actor)):
    return build_control_catalog(actor.tenant_id)


@router.post("/api/control-catalog")
def configure_control(payload: ControlDefinitionRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    tenant_id = _require_tenant_for_config(actor)
    return {"control": upsert_control_definition(payload.model_dump(), tenant_id)}


@router.get("/api/risk-rules")
def risk_rules(actor: ActorContext = Depends(current_actor)):
    return build_risk_rules(actor.tenant_id)


@router.post("/api/risk-rules")
def configure_risk_rule(payload: RiskRuleRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    tenant_id = _require_tenant_for_config(actor)
    return {"risk_rule": upsert_risk_rule(payload.model_dump(), tenant_id)}


@router.get("/api/retention-policy")
def retention_policy(actor: ActorContext = Depends(current_actor)):
    tenant_id = _require_tenant_for_config(actor)
    return {"tenant_id": tenant_id, "retention_days": retention_days_for(tenant_id),
            "minimum_retention_days": MIN_RETENTION_DAYS}


@router.post("/api/retention-policy")
def configure_retention_policy(payload: RetentionPolicyRequest, actor: ActorContext = Depends(current_actor)):
    """set how long this organization keeps raw telemetry

    the maintenance worker deletes raw events past the window; derived
    governance records and the audit log are kept. null keeps everything
    """
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    tenant_id = _require_tenant_for_config(actor)
    try:
        policy = set_retention_days(tenant_id, payload.retention_days)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record_audit(actor_ref=actor.user_ref, action="retention.configure", tenant_id=tenant_id,
                 target_type="retention", target_id=tenant_id,
                 detail={"retention_days": payload.retention_days})
    return {"retention_policy": policy}


@router.get("/api/owner-policies")
def owner_policies(actor: ActorContext = Depends(current_actor)):
    return build_owner_policies()


@router.post("/api/owner-policies")
def configure_owner_policy(payload: OwnerPolicyRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    tenant_id = _require_tenant_for_config(actor)
    return {"owner_policy": upsert_owner_policy(payload.model_dump(), tenant_id)}


# user and role management is not exposed here; it lives on the org-admin plane
# (/api/org/users, /api/org/role-assignments) which enforces tenant scoping and sod


@router.get("/api/review-queue-policies")
def review_queue_policies(actor: ActorContext = Depends(current_actor)):
    return build_review_queue_policies()


@router.post("/api/review-queue-policies")
def configure_review_queue_policy(payload: ReviewQueuePolicyRequest, actor: ActorContext = Depends(current_actor)):
    try:
        require_config_write(actor)
    except AuthorizationError as error:
        raise_forbidden(error)
    tenant_id = _require_tenant_for_config(actor)
    return {"review_queue_policy": upsert_review_queue_policy(payload.model_dump(), tenant_id)}


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
    # a risk accepted under an exception that has since lapsed is not remediated;
    # expire first so the reopened finding blocks this release
    expire_due_exceptions()
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


# the only decisions the workflow understands; anything else is rejected
_ALLOWED_DECISIONS = {"approve", "reject", "accept_risk", "mitigate", "waive", "close"}


@router.post("/api/decisions")
def create_decision(payload: DecisionRequest, actor: ActorContext = Depends(current_actor)):
    if payload.decision not in _ALLOWED_DECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"decision must be one of {sorted(_ALLOWED_DECISIONS)}",
        )
    # gates, incidents and approval stages have dedicated guarded endpoints;
    # don't let the generic route bypass them
    if payload.target_type in {"deployment_gate", "incident", "approval_stage"}:
        raise HTTPException(
            status_code=400,
            detail=(
                "Use the dedicated endpoint for this target type: deployment gates via "
                "/api/deployment-gates/{id}/approve|reject, incidents via /api/incidents/{id}/close, "
                "approval stages via /api/approval-stages/{id}/decide"
            ),
        )
    try:
        target = load_decision_target(payload.target_type, payload.target_id)
    except RecordNotFound as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    # unsupported target_type raises ValueError -> global 400, distinct from 404
    target["target_type"] = payload.target_type
    try:
        require_decision(actor, target)
    except AuthorizationError as error:
        raise_forbidden(error)
    enforce_segregation_of_duties(actor, payload.target_type, target)
    enforce_stage_policy(actor, payload.target_type, target, payload.decision)
    decision = record_decision(payload.target_type, payload.target_id, payload.decision, payload.rationale, actor.user_ref)
    record_audit(actor_ref=actor.user_ref, action="review.decide", tenant_id=target.get("tenant_id"), target_type=payload.target_type, target_id=payload.target_id, detail={"decision": payload.decision})
    # these targets are gate blockers; without this the gate keeps reporting the
    # findings the reviewer just cleared until the next batch of telemetry
    if payload.target_type in {"risk_finding", "control_assessment", "change_event"} and target.get("application_name"):
        refresh_deployment_gates([{
            "tenant_id": target.get("tenant_id"),
            "project": target.get("project"),
            "environment": target.get("environment"),
            "application_name": target.get("application_name"),
        }])
    return {"decision": decision}


@router.get("/api/exceptions")
def exceptions(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    # never show a lapsed exception as still active
    expire_due_exceptions()
    return paginate(build_exceptions(scope), "exceptions", page)


def _validate_future_date(value: str) -> None:
    from datetime import UTC, datetime

    text = value.strip()
    for candidate in (text, f"{text}T00:00:00+00:00"):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            if parsed <= datetime.now(UTC):
                raise HTTPException(status_code=400, detail="expires_at must be a future date")
            return
        except ValueError:
            continue
    raise HTTPException(status_code=400, detail="expires_at must be an ISO date (YYYY-MM-DD) or datetime")


@router.post("/api/exceptions")
def create_exception_route(payload: ExceptionRequest, actor: ActorContext = Depends(current_actor)):
    _validate_future_date(payload.expires_at)
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
    # sdk.health is tenant-stamped at ingestion, so scope reads by tenant like everything else
    return _event_page(scope, page, "sdk_health", event_type="sdk.health")


@router.get("/api/traces")
def traces(scope: ScopeFilter = Depends(scoped_dependency), page: PageParams = Depends()):
    return build_traces_page(scope, limit=page.limit, offset=page.offset)


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

"""getting-started checklist computed from the org's real state"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import ActorContext, current_actor
from app.services.authorization import DECISION_ROLES
from app.storage.attestation_keys import tenant_requires_attestation
from app.storage.audit import count_audit_logs
from app.storage.ingestion_keys import list_ingestion_keys
from app.storage.intake import list_intake
from app.storage.raw_events import count_scoped_events
from app.storage.saml import load_saml_configuration
from app.storage.sso import load_sso_configuration
from app.storage.workflow import list_owner_assignments, list_platform_users, list_role_assignments

router = APIRouter()


@router.get("/api/onboarding")
def onboarding(actor: ActorContext = Depends(current_actor)) -> dict[str, Any]:
    if actor.is_super_admin or not actor.tenant_id:
        raise HTTPException(status_code=403, detail="Getting started is an organization view")
    tenant_id = actor.tenant_id

    keys = [k for k in list_ingestion_keys(tenant_id) if k.get("status") == "active"]
    event_count = count_scoped_events(tenant_id=tenant_id)
    from app.storage.entities import tenant_application_stats

    app_count = int((tenant_application_stats().get(tenant_id) or {}).get("app_count") or 0)
    intake_count = len(list_intake(tenant_id=tenant_id))
    users = [u for u in list_platform_users(tenant_id=tenant_id) if u.get("status") == "active"]
    decision_holders = {
        a["user_ref"]
        for a in list_role_assignments(tenant_id=tenant_id)
        if a.get("status") == "active" and a.get("role") in DECISION_ROLES
    }
    owners_named = sum(1 for o in list_owner_assignments(tenant_id=tenant_id) if o.get("status") == "assigned")
    sso = load_sso_configuration(tenant_id)
    saml = load_saml_configuration(tenant_id)
    identity_connected = bool((sso or {}).get("enabled")) or bool((saml or {}).get("enabled"))
    attestation = tenant_requires_attestation(tenant_id)
    packets = count_audit_logs(tenant_id=tenant_id, action="compliance.audit_packet")

    steps = [
        {
            "id": "create_key",
            "title": "Create an ingestion key",
            "why": "Each key is bound to your organization, so telemetry can never be attributed to anyone else.",
            "done": bool(keys),
            "detail": f"{len(keys)} active key(s)" if keys else "No active key yet",
            "route": "identity",
            "action": "Create a key under Identity & Integrations",
        },
        {
            "id": "send_events",
            "title": "Instrument one application",
            "why": "Your inventory, risk findings and control evidence are derived from what actually runs.",
            "done": event_count > 0,
            "detail": f"{event_count} events received" if event_count else "No events received yet",
            "route": "guide",
            "action": "Install the SDK and send the first event",
        },
        {
            "id": "first_system",
            "title": "See your first AI system",
            "why": "Systems appear automatically from telemetry. Register planned ones through Intake so they are tiered before they ship.",
            "done": app_count > 0 or intake_count > 0,
            "detail": f"{app_count} discovered, {intake_count} submitted through intake",
            "route": "inventory" if app_count else "intake",
            "action": "Open the inventory" if app_count else "Submit a use case through Intake",
        },
        {
            "id": "invite_reviewers",
            "title": "Invite the people who decide",
            "why": "Administrators cannot approve work. Reviews and release gates need at least one governance_admin, risk_owner, control_owner or governance_reviewer.",
            "done": bool(decision_holders),
            "detail": f"{len(decision_holders)} user(s) hold a decision role; {len(users)} active users",
            "route": "team",
            "action": "Invite a reviewer under People & Access",
        },
        {
            "id": "name_owners",
            "title": "Name an accountable owner for each system",
            "why": "Regulators and auditors ask who is accountable. Owner follow-ups stay open until a named person accepts.",
            "done": owners_named > 0,
            "detail": f"{owners_named} owner(s) named",
            "route": "reviews",
            "action": "Assign owners under Review Work",
        },
        {
            "id": "sign_evidence",
            "title": "Require signed eval evidence for releases",
            "why": "Without a registered attestation key, any passing eval counts. With one, only evals signed by your CI satisfy a gate.",
            "done": attestation,
            "detail": "Enforced" if attestation else "Not enforced (recommended)",
            "route": "identity",
            "action": "Register an attestation key under Identity & Integrations",
            "optional": True,
        },
        {
            "id": "connect_identity",
            "title": "Connect your identity provider",
            "why": "SSO and SCIM give you automated joiner/leaver control, which SOC 2 and HIPAA both expect.",
            "done": identity_connected,
            "detail": "Connected" if identity_connected else "Not connected (recommended)",
            "route": "identity",
            "action": "Configure OpenID Connect or SAML under Identity & Integrations",
            "optional": True,
        },
        {
            "id": "export_packet",
            "title": "Export your first audit packet",
            "why": "The packet is what you hand to an auditor: inventory, AI-BOM, control evidence, decisions and the verified audit trail.",
            "done": packets > 0,
            "detail": f"{packets} packet(s) exported",
            "route": "compliance",
            "action": "Export from Compliance",
        },
    ]
    required = [s for s in steps if not s.get("optional")]
    return {
        "steps": steps,
        "completed": sum(1 for s in required if s["done"]),
        "required": len(required),
        "complete": all(s["done"] for s in required),
        "ingestion_key_hint": keys[0]["key_id"] if keys else None,
    }

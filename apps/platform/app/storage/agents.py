"""agent registry and runtime posture derivation

registry: each agent has an owner, autonomy level, tool allow-list, and a
capability profile (untrusted input, sensitive data, external action). posture:
observed agent.run / tool.call telemetry is reconciled against the registry to
derive risk findings, which flow into the risk register like any other risk
"""

from __future__ import annotations

from typing import Any

from .entities import decode_json, encode_json, entity_id
from .raw_events import connect

AUTONOMY_LEVELS = {
    0: "tool-assisted (human performs the task; AI suggests)",
    1: "conditional (AI acts only on explicit approval)",
    2: "supervised (AI acts; human reviews before effect)",
    3: "delegated (AI acts within bounds; human monitors)",
    4: "fully autonomous (AI plans and acts; human informed)",
}

# risk rules this module derives; registered in the catalog but evaluated here,
# not by the generic signal evaluator
AGENT_RISK_RULES = [
    {
        "rule_id": "RISK-AGT-SHADOW",
        "name": "Unregistered (shadow) agent observed at runtime",
        "signal": "unregistered_agent",
        "severity": "High",
        "confidence": 0.9,
        "framework_refs": ["OWASP Agentic ASI10", "NIST AI RMF MAP 1.1", "ISO/IEC 42001 A.6.2.6"],
        "rationale": "An agent acting in production that no one registered has no accountable owner, "
        "autonomy bound, or tool allow-list — rogue-agent risk.",
    },
    {
        "rule_id": "RISK-AGT-TOOL",
        "name": "Agent used a tool outside its allow-list",
        "signal": "unauthorized_tool",
        "severity": "High",
        "confidence": 0.9,
        "framework_refs": ["OWASP Agentic ASI02", "OWASP Agentic ASI03", "NIST AI RMF MANAGE 2.3"],
        "rationale": "Tool use beyond the sanctioned allow-list is the primary agentic privilege-escalation "
        "and tool-misuse vector.",
    },
    {
        "rule_id": "RISK-AGT-TRIFECTA",
        "name": "Agent holds the lethal trifecta without a human checkpoint",
        "signal": "agent_trifecta",
        "severity": "Critical",
        "confidence": 0.85,
        "framework_refs": ["OWASP Agentic ASI01", "OWASP Agentic ASI09", "NIST AI RMF MANAGE 1.3"],
        "rationale": "Untrusted input + sensitive data access + external action in one agent lets a single "
        "injected instruction exfiltrate data; Meta's Rule of Two says no more than two of the three "
        "may coexist without human supervision.",
    },
    {
        "rule_id": "RISK-AGT-AUTONOMY",
        "name": "High-autonomy agent without human oversight checkpoint",
        "signal": "autonomy_without_oversight",
        "severity": "High",
        "confidence": 0.8,
        "framework_refs": ["OWASP Agentic ASI09", "EU AI Act Art 14", "NIST AI RMF GOVERN 1.5"],
        "rationale": "Agents at autonomy level 3+ act within bounds on their own; without a declared human "
        "checkpoint there is no way to interrupt or override (EU AI Act Art 14 human oversight).",
    },
]


def init_agents() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_registry (
                agent_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                application_name TEXT,
                description TEXT,
                owner_ref TEXT NOT NULL,
                autonomy_level INTEGER NOT NULL DEFAULT 1,
                allowed_tools TEXT NOT NULL,
                processes_untrusted_input INTEGER NOT NULL DEFAULT 0,
                accesses_sensitive_data INTEGER NOT NULL DEFAULT 0,
                can_act_externally INTEGER NOT NULL DEFAULT 0,
                human_checkpoint INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_agent_registry_tenant ON agent_registry(tenant_id)")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_registry_name ON agent_registry(tenant_id, agent_name)"
        )


def _row(row: Any) -> dict[str, Any]:
    record = dict(row)
    record["allowed_tools"] = decode_json(record.get("allowed_tools"), [])
    for flag in ("processes_untrusted_input", "accesses_sensitive_data", "can_act_externally", "human_checkpoint"):
        record[flag] = bool(record.get(flag))
    record["autonomy_level_label"] = AUTONOMY_LEVELS.get(int(record.get("autonomy_level") or 0))
    return record


def register_agent(
    *,
    tenant_id: str,
    agent_name: str,
    owner_ref: str,
    autonomy_level: int,
    allowed_tools: list[str],
    processes_untrusted_input: bool,
    accesses_sensitive_data: bool,
    can_act_externally: bool,
    human_checkpoint: bool,
    application_name: str | None,
    description: str | None,
    created_by: str | None,
) -> dict[str, Any]:
    agent_id = entity_id("agent", tenant_id, agent_name)
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO agent_registry (
                agent_id, tenant_id, agent_name, application_name, description, owner_ref, autonomy_level,
                allowed_tools, processes_untrusted_input, accesses_sensitive_data, can_act_externally,
                human_checkpoint, status, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'), datetime('now'))
            ON CONFLICT(agent_id) DO UPDATE SET
                application_name=excluded.application_name,
                description=excluded.description,
                owner_ref=excluded.owner_ref,
                autonomy_level=excluded.autonomy_level,
                allowed_tools=excluded.allowed_tools,
                processes_untrusted_input=excluded.processes_untrusted_input,
                accesses_sensitive_data=excluded.accesses_sensitive_data,
                can_act_externally=excluded.can_act_externally,
                human_checkpoint=excluded.human_checkpoint,
                status='active',
                updated_at=datetime('now')
            """,
            (
                agent_id,
                tenant_id,
                agent_name,
                application_name,
                description,
                owner_ref,
                int(autonomy_level),
                encode_json(sorted(set(allowed_tools))),
                1 if processes_untrusted_input else 0,
                1 if accesses_sensitive_data else 0,
                1 if can_act_externally else 0,
                1 if human_checkpoint else 0,
                created_by,
            ),
        )
        return _row(connection.execute("SELECT * FROM agent_registry WHERE agent_id = ?", (agent_id,)).fetchone())


def list_registered_agents(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM agent_registry WHERE tenant_id = ? ORDER BY agent_name", (tenant_id,)
        ).fetchall()
    return [_row(row) for row in rows]


def load_registered_agent(agent_id: str, tenant_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM agent_registry WHERE agent_id = ? AND tenant_id = ?", (agent_id, tenant_id)
        ).fetchone()
    return None if row is None else _row(row)


def retire_agent(agent_id: str, tenant_id: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute(
            "SELECT 1 FROM agent_registry WHERE agent_id = ? AND tenant_id = ?", (agent_id, tenant_id)
        ).fetchone()
        if row is None:
            raise ValueError("agent not found in this organization")
        connection.execute(
            "UPDATE agent_registry SET status = 'retired', updated_at = datetime('now') WHERE agent_id = ?",
            (agent_id,),
        )
        return _row(connection.execute("SELECT * FROM agent_registry WHERE agent_id = ?", (agent_id,)).fetchone())


# --- posture derivation ----------------------------------------------------------


def _observed_agent_activity(connection, tenant_id: str) -> dict[str, dict[str, Any]]:
    """group agent.run and tool.call telemetry by agent name

    a tool.call is attributed to an agent when it shares a trace with the
    agent's run, or via the step list when present
    """
    runs = connection.execute(
        """
        SELECT name, trace_id, application_name, project, environment, attributes, observed_at
        FROM governance_observed_events WHERE entity_type = 'agent.run' AND tenant_id = ?
        """,
        (tenant_id,),
    ).fetchall()
    tools = connection.execute(
        """
        SELECT name, trace_id, attributes FROM governance_observed_events
        WHERE entity_type = 'tool.call' AND tenant_id = ?
        """,
        (tenant_id,),
    ).fetchall()
    tools_by_trace: dict[str, set[str]] = {}
    for tool in tools:
        tools_by_trace.setdefault(tool["trace_id"], set()).add(tool["name"])

    activity: dict[str, dict[str, Any]] = {}
    for run in runs:
        entry = activity.setdefault(
            run["name"],
            {
                "agent_name": run["name"],
                "application_name": run["application_name"],
                "project": run["project"],
                "environment": run["environment"],
                "run_count": 0,
                "trace_ids": set(),
                "tools_used": set(),
                "last_seen": None,
            },
        )
        entry["run_count"] += 1
        entry["trace_ids"].add(run["trace_id"])
        entry["tools_used"].update(tools_by_trace.get(run["trace_id"], set()))
        attrs = decode_json(run["attributes"], {}) if isinstance(run["attributes"], str) else (run["attributes"] or {})
        for step in attrs.get("steps") or []:
            if isinstance(step, dict) and step.get("tool"):
                entry["tools_used"].add(str(step["tool"]))
        if entry["last_seen"] is None or run["observed_at"] > entry["last_seen"]:
            entry["last_seen"] = run["observed_at"]
    return activity


def compute_agent_posture(tenant_id: str) -> dict[str, Any]:
    """reconcile observed agent activity against the registry, read-only"""
    registered = {agent["agent_name"]: agent for agent in list_registered_agents(tenant_id)}
    with connect() as connection:
        activity = _observed_agent_activity(connection, tenant_id)

    agents: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for name, obs in activity.items():
        registration = registered.get(name)
        entry = {
            "agent_name": name,
            "application_name": obs["application_name"],
            "registered": registration is not None and registration.get("status") == "active",
            "run_count": obs["run_count"],
            "tools_used": sorted(obs["tools_used"]),
            "last_seen": obs["last_seen"],
            "issues": [],
        }
        if registration is None or registration.get("status") != "active":
            entry["issues"].append("unregistered_agent")
            findings.append({"rule_id": "RISK-AGT-SHADOW", "agent": name, "obs": obs, "summary": f"Agent '{name}' ran {obs['run_count']}x but is not registered"})
        else:
            entry["owner_ref"] = registration["owner_ref"]
            entry["autonomy_level"] = registration["autonomy_level"]
            unauthorized = sorted(set(obs["tools_used"]) - set(registration["allowed_tools"]))
            if unauthorized:
                entry["issues"].append("unauthorized_tool")
                entry["unauthorized_tools"] = unauthorized
                findings.append({"rule_id": "RISK-AGT-TOOL", "agent": name, "obs": obs, "summary": f"Agent '{name}' used tools outside its allow-list: {', '.join(unauthorized)}"})
            trifecta = (
                registration["processes_untrusted_input"]
                and registration["accesses_sensitive_data"]
                and registration["can_act_externally"]
                and not registration["human_checkpoint"]
            )
            if trifecta:
                entry["issues"].append("agent_trifecta")
                findings.append({"rule_id": "RISK-AGT-TRIFECTA", "agent": name, "obs": obs, "summary": f"Agent '{name}' combines untrusted input, sensitive data, and external action with no human checkpoint"})
            if int(registration["autonomy_level"]) >= 3 and not registration["human_checkpoint"]:
                entry["issues"].append("autonomy_without_oversight")
                findings.append({"rule_id": "RISK-AGT-AUTONOMY", "agent": name, "obs": obs, "summary": f"Agent '{name}' is autonomy level {registration['autonomy_level']} with no human checkpoint"})
        agents.append(entry)

    # registered agents never observed at runtime are reported too (dormant)
    for name, registration in registered.items():
        if name not in activity and registration.get("status") == "active":
            agents.append(
                {
                    "agent_name": name,
                    "application_name": registration.get("application_name"),
                    "registered": True,
                    "run_count": 0,
                    "tools_used": [],
                    "last_seen": None,
                    "owner_ref": registration["owner_ref"],
                    "autonomy_level": registration["autonomy_level"],
                    "issues": [],
                }
            )

    return {
        "tenant_id": tenant_id,
        "agents": sorted(agents, key=lambda item: item["agent_name"]),
        "summary": {
            "observed": len(activity),
            "registered": sum(1 for a in registered.values() if a.get("status") == "active"),
            "shadow": sum(1 for a in agents if "unregistered_agent" in a["issues"]),
            "with_issues": sum(1 for a in agents if a["issues"]),
        },
        "_findings": findings,
    }


def refresh_agent_posture(tenant_ids: list[str] | None = None) -> None:
    """derive agent risk findings into the risk register, preserving reviewer
    decisions; tenant_ids limits to the tenants an ingest touched, None does all"""
    from .governance_policy import upsert_rule_finding

    rules = {rule["rule_id"]: rule for rule in AGENT_RISK_RULES}
    with connect() as connection:
        tenants = [
            row["tenant_id"]
            for row in connection.execute(
                "SELECT DISTINCT tenant_id FROM governance_observed_events WHERE entity_type = 'agent.run' AND tenant_id IS NOT NULL"
            ).fetchall()
        ]
    if tenant_ids is not None:
        tenants = [t for t in tenants if t in set(tenant_ids)]
    for tenant_id in tenants:
        posture = compute_agent_posture(tenant_id)
        with connect() as connection:
            for finding in posture["_findings"]:
                obs = finding["obs"]
                app_context = {
                    "tenant_id": tenant_id,
                    "project": obs["project"],
                    "environment": obs["environment"],
                    "application_name": obs["application_name"] or finding["agent"],
                }
                # evidence events only need trace ids for linkage
                evidence = [{"trace_id": trace_id} for trace_id in sorted(obs["trace_ids"])]
                rule = dict(rules[finding["rule_id"]])
                # agent-specific rule id so two shadow agents don't collapse into
                # one finding
                rule["rule_id"] = f"{rule['rule_id']}:{finding['agent']}"
                upsert_rule_finding(connection, app_context, rule, evidence, finding["summary"])


def public_posture(posture: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in posture.items() if not key.startswith("_")}


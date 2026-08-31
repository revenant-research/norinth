# RFC: Governance policy engine

**Status:** Implemented. The engine landed as one change set: policy storage
and validation with the seeded default (`storage/policy_engine.py`, migration
21), the stage engine for intake and vendor reviews, gate requirements from
policy, the vendor registry with the `RISK-VND-001` telemetry rule,
recertification clocks in the maintenance worker, the builder UI and packet
sections, and policy-declared intake fields. Deviations from the sketch below:
risk tiers key by the platform's real tiers (`limited`/`elevated`/`high`); a
stage's role requirement is an authority floor (a role granting at least the
named role's permissions satisfies it), which keeps the seeded single-stage
default byte-compatible with the pre-policy permission check; approval stages
carry denormalized scope columns and a `review_round` so vendor re-reviews get
fresh stage rows; and `vendor_registry` gains `submitted_by` (the review
maker) and `review_round`. In the builder UI, the sketch's JSON view became a
read-only raw-document disclosure in the history section: the working surface
edits each approval path directly as its pipeline of steps, because the
people who own governance policy think in approvers, not JSON. The document
stays the stored truth either way.

## Problem

Norinth's governance workflow is hardcoded. An AI use case is submitted through
intake, one review task is seeded, one holder of a decision role approves or
rejects it, and the lifecycle statuses (`submitted → approved / rejected /
recertified / retired`) are fixed in `storage/intake.py`. Release gates check a
fixed evidence tuple (open risks, missing controls, material changes, linked
prompt version, passing — optionally attested — evals). The only configurable
pieces today are routing and ownership (`review_queue_policies`,
`owner_assignment_policies`) and the per-tenant eval-attestation requirement.

Enterprises do not govern this way. A high-risk use case at a health system
needs security review, then legal sign-off, then business-owner acceptance — in
that order, by three different people. A low-risk internal tool needs one
reviewer. EU AI Act conformity flows are explicitly multi-role. Third-party AI
vendors need their own registry and review cycle, and nothing in the product
models them at all. Every serious deployment will ask for its own shape of
approval, lifecycle cadence, and vendor governance.

The obvious answer — a free-form, no-code workflow designer — is the wrong one
for this product. Norinth's audit story depends on decisions having **fixed,
provable semantics**: "approved" means evidence was present, versions were
bound, the maker was not the checker, and the decision is terminal and
hash-chained. `docs/threat-model.md` states the same principle for roles: one
install carries one definition, so a decision carries the same meaning
everywhere. A designer where each administrator invents states and transitions
reintroduces exactly the ambiguity the audit packet exists to kill — an auditor
could no longer say what an approval meant without reverse-engineering a
flowchart.

## Goal

Configurability as **declarative, versioned policy riding the evidence spine** —
not a workflow engine. Each installation (and each organization on it) can
declare *how many* approvals a use case needs, *which roles* give them, *how
often* things recertify, *what evidence* a gate demands, and *how vendors are
reviewed — while the meaning of a decision stays fixed and machine-checkable.
The policy itself becomes evidence: every decision records the policy version
that governed it, and the audit packet can show "this approval satisfied
3-stage policy v4, in force at decision time," with the policy's own history
hash-anchored.

That last property turns configurability from a threat to the audit story into
a strengthening of it, and it is a claim a forms-and-workflow GRC product
cannot make: the workflow is code, versioned, diffable, and every decision
proves which version it followed.

## Non-goals

- A visual state-machine designer, custom statuses, or user-defined
  transitions. States and their meanings stay fixed; policy only parameterizes
  the fixed machine.
- An expression or condition language in policy documents (v1). Conditions are
  limited to keying by **risk tier** and **environment** — no user-authored
  predicates to parse, sandbox, or audit.
- Per-organization role *definitions*. Roles and their permissions remain
  platform-wide (threat model §3); policy chooses *which* roles decide, never
  what a role may do.
- SLA/escalation designers, transition webhooks, or cross-system orchestration.
  Due/escalation days stay in `review_queue_policies`; webhooks already exist.
- Questionnaire campaigns or policy-pack *content* authoring (see the
  competitive roadmap's deliberately-not-building list and its reasons).

## Invariants (never configurable)

These are the product; everything in this RFC sits above them:

1. **Segregation of duties** — a maker never checks their own work, and no user
   decides two stages of the same subject.
2. **Decisions are terminal and append-only** (`record_decision` semantics from
   #96/#112). A stage, once decided, never changes.
3. **Every decision and every policy change is hash-chained in the audit log.**
4. **Gates are evidence-bound.** Policy can *tighten or select* the evidence a
   gate requires; it cannot approve without evidence or remove the version
   binding.
5. **Role semantics are platform-wide.** Policy references roles; it cannot
   mint or widen them.
6. **Custom intake fields obey the content boundary** conventions (typed,
   length-capped, documented as fields that must not carry PHI, like the
   incident title).

## Design

### 1. The policy document

A declarative JSON document, one **active** version per tenant, with the
platform default under `tenant_id = ''` following the existing
default-with-tenant-overlay pattern (`control_library`, `risk_rules`).

```json
{
  "schema": "governance-policy/v1",
  "intake": {
    "tiers": {
      "critical": {
        "stages": [
          {"role": "governance_reviewer", "label": "Security review"},
          {"role": "risk_owner",          "label": "Risk acceptance"},
          {"role": "governance_admin",    "label": "Final sign-off"}
        ],
        "mode": "sequence",
        "recertify_days": 180
      },
      "high":   {"stages": [{"role": "governance_reviewer"}, {"role": "risk_owner"}], "mode": "sequence", "recertify_days": 365},
      "medium": {"stages": [{"role": "governance_reviewer"}], "recertify_days": 365},
      "low":    {"stages": [{"role": "governance_reviewer"}]}
    },
    "fields": [
      {"key": "dpia_ref", "label": "DPIA reference", "type": "string", "max_length": 200, "required_tiers": ["high", "critical"]}
    ]
  },
  "gates": {
    "environments": {
      "production": {"require_attested_evals": true, "max_open_material_changes": 0},
      "*":          {"require_attested_evals": false}
    }
  },
  "vendors": {
    "stages": [{"role": "governance_reviewer"}, {"role": "governance_admin"}],
    "recertify_days": 365
  }
}
```

Validation on write: schema version known; every referenced role exists in
`role_permissions` and holds the decision permission its position requires;
stages non-empty; `mode` is `sequence` (default) or `parallel`;
`recertify_days` at/above a floor; field keys are identifier-shaped; unknown
keys rejected. Tiers absent from the document fall back to the platform
default's entry for that tier, so a tenant can override only what it cares
about.

Storage:

```sql
CREATE TABLE governance_policies (
    tenant_id      TEXT NOT NULL DEFAULT '',
    version        INTEGER NOT NULL,
    status         TEXT NOT NULL,           -- draft | active | superseded
    body           TEXT NOT NULL,           -- the JSON document
    body_hash      TEXT NOT NULL,           -- sha256 of canonical body
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    activated_at   TEXT,
    PRIMARY KEY (tenant_id, version)
);
```

Exactly one `active` row per tenant. Activation supersedes the previous
version in the same transaction and writes an audit entry
(`policy.activate`, detail: version, body_hash, diff summary). Writing
requires `config_write`; the org-admin/decision-role separation already
prevents the person who configures the policy from also deciding under it.

**The shipped default is today's behavior, exactly.** The platform seeds
`governance-policy/v1` version 1 for `tenant_id = ''` encoding the current
single-stage review per tier and the current gate evidence rules. An install
that never touches policy behaves bit-for-bit as it does now; the equivalence
is pinned by tests the way #119's fold was pinned against the full recompute.

### 2. Multi-stage approvals

New table, subordinate to the existing work items — `review_tasks` remains the
unit of work; stages are its checklist:

```sql
CREATE TABLE approval_stages (
    stage_id        TEXT PRIMARY KEY,
    tenant_id       TEXT,
    subject_type    TEXT NOT NULL,          -- review_task | vendor_review
    subject_id      TEXT NOT NULL,
    policy_tenant   TEXT NOT NULL,          -- which policy row governed
    policy_version  INTEGER NOT NULL,
    stage_index     INTEGER NOT NULL,
    required_role   TEXT NOT NULL,
    label           TEXT,
    status          TEXT NOT NULL,          -- pending | open | approved | rejected
    decision_id     TEXT,                   -- FK into governance_decisions
    decided_by      TEXT,
    created_at      TEXT NOT NULL,
    decided_at      TEXT
);
```

Semantics:

- Seeding a review reads the **active policy at that moment** and materializes
  its stages. In `sequence` mode stage 0 is `open` and the rest `pending`
  (opening as predecessors approve); in `parallel` mode all open at once.
- A stage decision goes through `record_decision` (append-only, terminal) with
  `target_type="approval_stage"`; the stage row links the decision id. SoD
  checks: the decider holds `required_role` in the tenant, is not the subject's
  maker, and **has not decided any other stage of this subject** — that last
  rule is what makes multiple stages mean multiple people.
- The subject approves only when every stage is `approved`; any rejection
  rejects the subject (terminal). `apply_decision_status` gains this roll-up.
- **In-flight subjects keep the policy version they started under.** Stages are
  materialized rows, so activating a new policy never rewrites open work; a
  decision is always judged by the policy in force when its review began, and
  the packet can prove which one that was.
- The notification and queue machinery (`review_queue_policies`, overdue and
  escalation aging, role-routed notifications) applies per open stage
  unchanged.

### 3. Gate requirements from policy

`upsert_deployment_gate` currently computes a fixed evidence tuple, with
`tenant_requires_attestation` as the one per-tenant knob. That knob generalizes:
the gate reads the active policy's `gates.environments` entry for its
environment (falling back to `"*"`, then the platform default) for
`require_attested_evals` and `max_open_material_changes`. Both may only
**tighten** relative to the floor (the floor is today's behavior: material
changes must be zero to approve; that stays the ceiling for
`max_open_material_changes`). The gate's evidence snapshot records the policy
version consulted, alongside the evidence it already records.
`tenant_requires_attestation` becomes a read of the policy, with the existing
attestation-keys behavior as the seeded default.

### 4. Vendors

A minimal registry — not vendor questionnaires:

```sql
CREATE TABLE vendor_registry (
    vendor_id       TEXT PRIMARY KEY,
    tenant_id       TEXT,
    name            TEXT NOT NULL,
    providers       TEXT NOT NULL,          -- JSON list of provider strings
    status          TEXT NOT NULL,          -- draft | under_review | approved | rejected | recertify_due | retired
    approved_models TEXT,                   -- JSON list, optional allow-list
    notes_ref       TEXT,                   -- evidence attachment id (Phase 3)
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    reviewed_at     TEXT
);
```

Vendor review runs through the same stage machinery
(`subject_type = "vendor_review"`, stages from `policy.vendors`). Recertification
is aged by the existing maintenance worker like exceptions are.

The evidence-engine tie-in, and the reason vendors belong in this product at
all: the registry joins **telemetry**. `sdk_events.provider` names every vendor
actually in production, so a new detection rule (`RISK-VND-001`, signal
`unreviewed_vendor`) raises a finding when observed provider usage has no
approved vendor entry — and, where an allow-list is set, when a model outside
`approved_models` appears. Vendor posture becomes *proven by production*, not a
spreadsheet: the same claim the agent registry already makes for agents.

### 5. Policy as evidence

- Every stage row and gate snapshot carries `(policy_tenant, policy_version)`.
- The audit packet gains a `governance_policy` section: the active body, its
  hash, and the activation history (who, when, hash) — which is already in the
  audit chain via `policy.activate` entries.
- Framework coverage (Phase 3 evidence types): the policy engine maps to the
  requirements about *having* a documented approval process (e.g. ISO/IEC
  42001's impact-assessment and approval controls) as **attested-by-policy**,
  while the stage records under it are **telemetry-proven** in the packet's
  proven/attested split.

### 6. The no-code UI

A builder page under the org admin plane that reads and writes the document:
tier cards with stage lists (role pickers from the platform's real roles),
gate toggles per environment, vendor stage list, custom-field editor. The
document is the truth — the UI is an editor over it, with a JSON view, a diff
view between versions, and an explicit **Activate** action that shows the diff
it is about to put in force. No layout canvas, no arrows.

## Rollout (units: PR rounds, each with teeth tests)

1. **Policy storage + validation + seeded default + read paths.** Equivalence
   tests pin default-policy behavior to current behavior.
2. **Stage engine for intake reviews** behind the policy (single-stage default
   produces today's rows; a multi-stage test proves ordering, SoD-across-
   stages, roll-up, rejection, and policy-version pinning of in-flight work).
3. **Gate requirements from policy**, generalizing
   `tenant_requires_attestation`.
4. **Vendor registry + review + the `unreviewed_vendor` telemetry rule.**
5. **Builder UI** (document editor, diff, activate) + packet rendering.
6. **Custom intake fields** (last: touches the intake form, API schema, and
   content-boundary docs together).

Each lands independently mergeable; the feature is invisible until an admin
activates a non-default policy.

## Security considerations

- The policy body is configuration, not code: no expressions, no templates, no
  evaluation of tenant-authored strings. Validation rejects unknown structure.
- Policy writes require `config_write`; activation is audited with the body
  hash, so a quietly weakened policy is as visible as a deleted audit row.
- Policy can only tighten gates, never below the shipped floor — a tenant
  cannot configure its way past evidence binding.
- Stage labels and field labels are rendered in the UI: length-capped and
  treated as text (the frontend already renders no raw HTML).
- The cross-stage SoD rule is enforced server-side in the decision path, not in
  the UI.

## Open questions

1. Should activating a policy itself require a second person (maker–checker on
   the policy)? Leaning yes for a later round via the same stage machinery
   (`subject_type = "policy_activation"`), shipped after v1 so the engine can
   govern itself.
2. Should a tier's stages be allowed to name the *same role twice* (two
   different people from one role)? v1 says yes implicitly — the
   distinct-decider rule forces two people; the question is whether the UI
   should surface it as an explicit "two approvals from role X" control.
3. Whether `vendor_registry.providers` should also match OTel `gen_ai.system`
   values — probably yes, same normalization the entities layer already does.

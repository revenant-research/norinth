// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useEffect, useState, type ReactNode } from "react";
import { getJson, postJson, type User } from "../api";
import {
  createPortableClient,
  explainPortableReason,
  portableStatusLabel,
  safePortableLink,
  type PortableClient,
  type PortableLinkResolver,
  type PortableRecord,
  type SystemWorkspace,
} from "../portable";
import {
  Badge,
  Button,
  Callout,
  Card,
  Heading,
  Inline,
  Stack,
  Text,
  TextArea,
  TextField,
} from "../design";
import { confirm } from "./confirm";
import { Section, EmptyState } from "./ui";
import {
  PortableIntegrationSettings,
  PortablePolicyDraft,
} from "./portableSettings";

export const localPortableClient = createPortableClient(
  (path, method, payload) =>
    method === "GET" ? getJson(path) : postJson(path, payload),
);
const displayedState = (record: PortableRecord) =>
  record.audited_at === "" ? "audit_pending" : record.state;
export const portableError = (e: unknown) =>
  e instanceof Error ? e.message : "The request failed.";
function Status({ value }: { value: string }) {
  return <Badge value={value}>{portableStatusLabel(value)}</Badge>;
}
function Guidance({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details>
      <summary>{title}</summary>
      <Text size="sm">{children}</Text>
    </details>
  );
}
function SourceLink({
  record,
  resolve,
  relation = "source",
}: {
  record: PortableRecord;
  resolve?: PortableLinkResolver;
  relation?: "source" | "evidence";
}) {
  const href = safePortableLink(resolve?.(record, relation) ?? null);
  return href ? (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {relation === "source" ? "Open in source platform" : "Open evidence"}
    </a>
  ) : null;
}
export function PortableSystemsView({
  user,
  client = localPortableClient,
  resolveLink,
}: {
  user: User;
  client?: PortableClient;
  resolveLink?: PortableLinkResolver;
}) {
  const [scope, setScope] = useState({ project: "", environment: "" });
  const [offset, setOffset] = useState(0);
  const [systems, setSystems] = useState<PortableRecord[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    client
      .systems(scope, offset)
      .then((result) => {
        if (!cancelled) {
          setSystems(result.systems);
          setHasMore(result.has_more);
        }
      })
      .catch((e) => {
        if (!cancelled) setError(portableError(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [client, scope, offset, refresh]);
  return (
    <Stack gap={4}>
      <Guidance title="How connected systems work">
        A source platform registers a stable system and its exact release
        configuration. Norinth checks the current policy and evidence before
        issuing a short-lived permission. The source platform must consume that
        permission and stop when permission is denied or unavailable. Telemetry
        alone does not enforce this.
      </Guidance>
      <Inline gap={3}>
        {(["project", "environment"] as const).map((field) => (
          <TextField
            key={field}
            label={field === "project" ? "Project" : "Environment"}
            value={scope[field]}
            placeholder={`All ${field}s`}
            onChange={(e) => {
              setScope({ ...scope, [field]: e.target.value });
              setOffset(0);
              setSelected("");
            }}
          />
        ))}
        <Button variant="secondary" onClick={() => setRefresh((v) => v + 1)}>
          Refresh connected systems
        </Button>
      </Inline>
      {error ? (
        <Callout tone="danger" title="Systems unavailable">
          {error}
        </Callout>
      ) : loading ? (
        <Text>Loading connected systems…</Text>
      ) : systems.length ? (
        <div className="record-list">
          {systems.map((system) => (
            <Card key={system.record_id} padding="md">
              <Inline justify="between">
                <Stack gap={2}>
                  <Heading level={2} size="lg">
                    {system.body.display_name}
                  </Heading>
                  <Text size="sm">
                    {system.project} / {system.environment} ·{" "}
                    {system.body.resource_type}
                  </Text>
                  <Status value={displayedState(system)} />
                </Stack>
                <Button
                  variant="secondary"
                  onClick={() => setSelected(system.record_id)}
                >
                  Open {system.body.display_name}
                </Button>
              </Inline>
            </Card>
          ))}
        </div>
      ) : (
        <EmptyState>
          No connected systems in this scope. Systems can be registered before
          production telemetry arrives.
        </EmptyState>
      )}
      <Inline gap={2}>
        <Button
          disabled={offset === 0 || loading}
          variant="secondary"
          onClick={() => {
            setOffset((v) => Math.max(0, v - 50));
            setSelected("");
          }}
        >
          Previous systems
        </Button>
        <Button
          disabled={!hasMore || loading}
          variant="secondary"
          onClick={() => {
            setOffset((v) => v + 50);
            setSelected("");
          }}
        >
          Next systems
        </Button>
      </Inline>
      {selected ? (
        <PortableSystemWorkspace
          key={selected}
          systemId={selected}
          client={client}
          user={user}
          resolveLink={resolveLink}
        />
      ) : null}
      {user.permissions.includes("config.write") ? (
        <PortableIntegrationSettings client={client} />
      ) : null}
    </Stack>
  );
}

// Embedding hosts supply transport and link resolution; there are no product
// URLs, cloud-specific types or assumptions about the host's user directory.
export function PortableSystemWorkspace({
  systemId,
  client,
  user,
  resolveLink,
}: {
  systemId: string;
  client: PortableClient;
  user: Pick<User, "user_ref" | "permissions">;
  resolveLink?: PortableLinkResolver;
}) {
  const [value, setValue] = useState<SystemWorkspace | null>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [offset, setOffset] = useState(0);
  const [pending, setPending] = useState(false);
  const [rationale, setRationale] = useState("");
  const [controls, setControls] = useState<{
    assessments: Record<string, any>[];
    basis: string;
  } | null>(null);
  const [controlError, setControlError] = useState("");
  const [controlRevision, setControlRevision] = useState<PortableRecord | null>(
    null,
  );
  useEffect(() => {
    let cancelled = false;
    setValue(null);
    setError("");
    setControlRevision(null);
    client
      .workspace(systemId, offset)
      .then((result) => {
        if (!cancelled) setValue(result);
      })
      .catch((e) => {
        if (!cancelled) setError(portableError(e));
      });
    return () => {
      cancelled = true;
    };
  }, [client, systemId, refresh, offset]);
  useEffect(() => {
    let cancelled = false;
    setControls(null);
    setControlError("");
    if (controlRevision)
      client
        .controls(systemId, controlRevision.record_id)
        .then((result) => {
          if (!cancelled) setControls(result);
        })
        .catch((e) => {
          if (!cancelled) setControlError(portableError(e));
        });
    return () => {
      cancelled = true;
    };
  }, [client, systemId, controlRevision]);
  async function decide(record: PortableRecord, decision: string) {
    if (
      !(await confirm({
        title: "Record governance decision",
        body: `${decision.replaceAll("_", " ")} for ${record.body.manifest?.revision || record.body.display_name || record.record_id}. ${rationale}`,
        confirmLabel: "Record decision",
      }))
    )
      return;
    setPending(true);
    try {
      await client.decide(
        record.record_id,
        decision,
        rationale,
        record.body_digest,
      );
      setRationale("");
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(portableError(e));
    } finally {
      setPending(false);
    }
  }
  function decisionButton(
    record: PortableRecord,
    decision: string,
    permission: string,
    label: string,
  ) {
    if (
      !user.permissions.includes(permission) ||
      record.created_by === user.user_ref
    )
      return null;
    return (
      <Button
        disabled={pending || rationale.trim().length < 12}
        variant="secondary"
        onClick={() => void decide(record, decision)}
      >
        {label}
      </Button>
    );
  }
  function auditButton(record: PortableRecord, permission: string) {
    if (record.audited_at !== "" || !user.permissions.includes(permission))
      return null;
    return (
      <Button
        disabled={pending}
        variant="secondary"
        onClick={async () => {
          setPending(true);
          try {
            await client.retryAudit(record.record_id);
            setRefresh((v) => v + 1);
          } catch (e) {
            setError(portableError(e));
          } finally {
            setPending(false);
          }
        }}
      >
        Retry audit recording
      </Button>
    );
  }
  if (!value)
    return error ? (
      <Callout tone="danger" title="System unavailable">
        {error}
      </Callout>
    ) : (
      <Text>Loading system…</Text>
    );
  const system = value.system;
  const active = value.active_policy;
  const more = [
    "revisions",
    "policies",
    "authorizations",
    "receipts",
    "decisions",
    "observations",
    "verifications",
    "packs",
  ].some((kind) => value[`${kind}_has_more`]);
  return (
    <Section
      title={system.body.display_name}
      description={`${system.project} / ${system.environment} · ${system.body.purpose || "Purpose has not been supplied"}`}
    >
      <Stack gap={4}>
        {error ? (
          <Callout tone="danger" title="Decision not recorded">
            {error}
          </Callout>
        ) : null}
        <Inline gap={3}>
          <Status value={displayedState(system)} />
          <Text size="sm">Stable system ID: {system.record_id}</Text>
          <SourceLink record={system} resolve={resolveLink} />
          <Button variant="secondary" onClick={() => setRefresh((v) => v + 1)}>
            Recheck this system
          </Button>
        </Inline>
        <Card padding="md">
          <Stack gap={2}>
            <Text>
              Runtime policy:{" "}
              {active ? displayedState(active) : "not configured"}. Executor:{" "}
              {value.integration.body.name} ({displayedState(value.integration)}
              ).
            </Text>
            <Text>
              Runtime enforcement: requires the source platform to consume each
              permission. Norinth has not verified that the executor intercepts
              every action.
            </Text>
          </Stack>
        </Card>
        <Guidance title="Approval, permission, and verification are different">
          System approval accepts the stated purpose. Revision approval records
          a person's review of one immutable configuration. Current release
          eligibility can change as evidence ages or policy changes. A consumed
          permission records an authorization check; a receipt records what the
          executor reports; independent verification checks whether a correction
          worked.
        </Guidance>
        <TextArea
          label="Decision rationale"
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          minLength={12}
          maxLength={2000}
          placeholder="Explain why this exact decision is justified."
        />
        <Inline gap={2}>
          {auditButton(system, "review.decide")}
          {system.state === "planned"
            ? decisionButton(
                system,
                "approve_system",
                "review.decide",
                "Approve system purpose",
              )
            : null}
          {system.state !== "retired"
            ? decisionButton(
                system,
                "retire_system",
                "lifecycle.manage",
                "Retire system",
              )
            : null}
        </Inline>
        <Section title="Revisions and current release eligibility">
          <Guidance title="What does this status mean?">
            Eligible means the current policy and fresh evidence permit this
            exact revision. Missing or stale evidence is unknown. Automatic
            releases must be explicitly enabled in a policy approved by another
            person. The original human review history is preserved.
          </Guidance>
          {value.revisions.length ? (
            value.revisions.map((revision) => {
              const live = value.eligibility[revision.record_id];
              return (
                <Card padding="md" key={revision.record_id}>
                  <Stack gap={2}>
                    <Inline gap={2}>
                      <Heading level={3} size="lg">
                        {revision.body.manifest.revision}
                      </Heading>
                      <Text>Historical review:</Text>
                      <Status value={displayedState(revision)} />
                      <Text>Current release:</Text>
                      <Status value={live?.outcome || "unknown"} />
                    </Inline>
                    <Text size="sm">
                      {live
                        ? live.reasons.map(explainPortableReason).join(" ") ||
                          "Current evidence and policy checks pass."
                        : "Current eligibility is unavailable."}{" "}
                      Checked {live?.checked_at || "not yet"}.
                    </Text>
                    <Text size="sm">
                      Models:{" "}
                      {revision.body.manifest.models.join(", ") ||
                        "none declared"}
                      . Tools:{" "}
                      {revision.body.manifest.tools.join(", ") ||
                        "none declared"}
                      . Autonomy: {revision.body.manifest.autonomy_level}.
                    </Text>
                    <details>
                      <summary>Exact release configuration and digest</summary>
                      <pre>{JSON.stringify(revision.body, null, 2)}</pre>
                    </details>
                    <Inline gap={2}>
                      {auditButton(revision, "gate.decide")}
                      {revision.state === "pending_review" &&
                      live &&
                      ["allow", "requires_review"].includes(live.outcome) &&
                      !live.reasons.some(
                        (reason) => reason !== "revision_requires_review",
                      )
                        ? decisionButton(
                            revision,
                            "approve_revision",
                            "gate.decide",
                            "Approve this revision",
                          )
                        : null}
                      <Button
                        variant="secondary"
                        onClick={() => setControlRevision(revision)}
                      >
                        Assess controls for {revision.body.manifest.revision}
                      </Button>
                      <SourceLink record={revision} resolve={resolveLink} />
                    </Inline>
                  </Stack>
                </Card>
              );
            })
          ) : (
            <EmptyState>
              No revisions submitted. Registration does not require telemetry.
            </EmptyState>
          )}
          {controlError ? (
            <Callout tone="danger" title="Control evidence unavailable">
              {controlError}
            </Callout>
          ) : controls ? (
            <Stack gap={2}>
              <Heading level={3} size="lg">
                Control assessment: {controlRevision?.body.manifest.revision}
              </Heading>
              <Text>{controls.basis}</Text>
              {controls.assessments.length ? (
                controls.assessments.map((item) => (
                  <Card
                    padding="md"
                    key={`${item.pack_id}/${item.pack_version}/${item.control_id}`}
                  >
                    <Text>
                      {item.name} · {item.pack_id} {item.pack_version}
                    </Text>
                    <Status value={item.status} />
                    <Text size="sm">
                      {item.framework_refs.join(", ")} ·{" "}
                      {item.reasons.map(explainPortableReason).join(" ") ||
                        (item.status === "not_applicable"
                          ? "This control does not apply to this resource type."
                          : "Evidence requirements pass for this revision.")}
                    </Text>
                  </Card>
                ))
              ) : (
                <EmptyState>
                  No active control packs in this scope. No framework compliance
                  has been inferred.
                </EmptyState>
              )}
            </Stack>
          ) : null}
        </Section>
        <Section
          title="Execution and correction receipts"
          description="An executor reporting success is not proof that a correction worked."
        >
          {value.receipts.length ? (
            value.receipts.map((receipt) => (
              <Card padding="md" key={receipt.record_id}>
                <Inline gap={2}>
                  <Text>
                    {receipt.body.purpose}: {receipt.body.outcome} · historical
                    receipt
                  </Text>
                  <Badge
                    value={receipt.audited_at ? receipt.state : "audit_pending"}
                  />
                </Inline>
                <Text size="sm">
                  Reported {receipt.created_at} · {receipt.body.evidence_ref}
                </Text>
                <SourceLink
                  record={receipt}
                  resolve={resolveLink}
                  relation="evidence"
                />
              </Card>
            ))
          ) : (
            <EmptyState>
              No execution receipts. There is no execution or correction
              evidence to claim.
            </EmptyState>
          )}
        </Section>
        <Section title="Authorization and evidence history">
          {value.authorizations.map((record) => (
            <Card padding="md" key={record.record_id}>
              <Inline gap={2}>
                <Text>
                  {record.body.request.purpose}{" "}
                  {record.body.request.action?.capability || "release"}
                </Text>
                <Status value={record.body.outcome} />
                <Text size="sm">Permit state: {record.state}</Text>
              </Inline>
              <Text size="sm">
                {record.body.reasons.map(explainPortableReason).join(" ") ||
                  "Policy allowed the requested scope."}{" "}
                · {record.created_at}
              </Text>
            </Card>
          ))}
          {value.observations.map((record) => (
            <Card padding="md" key={record.record_id}>
              <Inline gap={2}>
                <Text>{record.body.check_id}</Text>
                <Status value={record.body.result} />
                <Text size="sm">Observed {record.body.observed_at}</Text>
              </Inline>
              <Text size="sm">{record.body.evidence_ref}</Text>
              <SourceLink
                record={record}
                resolve={resolveLink}
                relation="evidence"
              />
            </Card>
          ))}
          {value.verifications.map((record) => (
            <Text key={record.record_id} size="sm">
              Independent check {record.created_at}: receipt{" "}
              {record.body.receipt_id}, observation {record.body.observation_id}
            </Text>
          ))}
        </Section>
        <Section title="Policies and decision history">
          {value.policies.map((record) => (
            <Card padding="md" key={record.record_id}>
              <Stack gap={2}>
                <Status value={displayedState(record)} />
                <Text size="sm">
                  {record.created_by} · {record.created_at}
                </Text>
                <Text>
                  Automatic releases:{" "}
                  {record.body.policy.allow_routine_releases
                    ? "explicitly enabled"
                    : "require a revision reviewer"}
                  . Evidence expires after{" "}
                  {record.body.policy.evidence_max_age_seconds} seconds.
                </Text>
                <details>
                  <summary>Operating limits and evidence sources</summary>
                  <pre>{JSON.stringify(record.body.policy, null, 2)}</pre>
                </details>
                {auditButton(record, "config.write")}
                {record.state === "draft"
                  ? decisionButton(
                      record,
                      "activate_policy",
                      "config.write",
                      "Activate operating policy",
                    )
                  : null}
              </Stack>
            </Card>
          ))}
          {value.packs.map((record) => (
            <Card padding="md" key={record.record_id}>
              <Text>
                {record.body.pack.pack_id} {record.body.pack.version}
              </Text>
              <Status value={displayedState(record)} />
              {auditButton(record, "config.write")}
              {record.state === "draft"
                ? decisionButton(
                    record,
                    "activate_pack",
                    "config.write",
                    "Activate control pack",
                  )
                : null}
            </Card>
          ))}
          {value.decisions.map((record) => (
            <Card padding="md" key={record.record_id}>
              <Text>
                {record.body.decision.replaceAll("_", " ")} ·{" "}
                {record.created_by}
              </Text>
              <Text size="sm">
                {record.body.rationale} · {record.created_at}
              </Text>
              {record.body.target_snapshot ? (
                <details>
                  <summary>Material reviewed for this decision</summary>
                  {record.body.target_snapshot.purpose ? (
                    <Text>
                      Reviewed purpose: {record.body.target_snapshot.purpose}
                    </Text>
                  ) : null}
                  <pre>
                    {JSON.stringify(
                      {
                        digest: record.body.target_body_digest,
                        material: record.body.target_snapshot,
                      },
                      null,
                      2,
                    )}
                  </pre>
                </details>
              ) : null}
            </Card>
          ))}
        </Section>
        <Inline gap={2}>
          <Button
            variant="secondary"
            disabled={offset === 0}
            onClick={() => setOffset((v) => Math.max(0, v - 100))}
          >
            Newer history
          </Button>
          <Button
            variant="secondary"
            disabled={!more}
            onClick={() => setOffset((v) => v + 100)}
          >
            Older history
          </Button>
        </Inline>
        {user.permissions.includes("config.write") ? (
          <PortablePolicyDraft
            system={system}
            integration={value.integration}
            client={client}
            onSaved={() => {
              setOffset(0);
              setRefresh((v) => v + 1);
            }}
          />
        ) : null}
      </Stack>
    </Section>
  );
}

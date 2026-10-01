// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useEffect, useState } from "react";
import { portableStatusLabel, type PortableClient, type PortableRecord } from "../portable";
import {
  Badge,
  Button,
  Callout,
  Card,
  Checkbox,
  Inline,
  SelectField,
  Stack,
  Text,
  TextArea,
  TextField,
} from "../design";
import { confirm } from "./confirm";
import { SecretReveal } from "./identity";
import { Section } from "./ui";

const words = (value: string) =>
  value
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter(Boolean);
const errorText = (e: unknown) =>
  e instanceof Error ? e.message : "The request failed.";
export function PortablePolicyDraft({
  system,
  integration,
  client,
  onSaved,
}: {
  system: PortableRecord;
  integration: PortableRecord;
  client: PortableClient;
  onSaved: () => void;
}) {
  const [sources, setSources] = useState<PortableRecord[]>([]);
  const [form, setForm] = useState({
    models: "",
    tools: "",
    resources: "",
    actions: "",
    remediation_actions: "",
    required_checks: "",
    trusted_sources: "",
    max_autonomy: 0,
    require_human_checkpoint: true,
    allow_external_action: false,
    allow_routine_releases: false,
    evidence_max_age_seconds: 86400,
    permit_ttl_seconds: 60,
  });
  const [parameters, setParameters] = useState<
    Record<string, Record<string, string>>
  >({});
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const capabilities = integration.body.capabilities as Array<{
    name: string;
    parameter_types: Record<string, string>;
  }>;
  useEffect(() => {
    let cancelled = false;
    async function loadSources() {
      const records: PortableRecord[] = [];
      for (let offset = 0; offset <= 1000000; offset += 100) {
        const result = await client.integrations(
          { project: system.project, environment: system.environment },
          offset,
        );
        if (cancelled) return;
        records.push(...result.integrations);
        if (!result.has_more) {
          setSources(
            records.filter(
              (r) =>
                r.state === "active" &&
                r.body.scopes.includes("observations:write"),
            ),
          );
          return;
        }
      }
      throw new Error("Evidence-source list exceeded the pagination limit.");
    }
    void loadSources().catch((e) => {
      if (!cancelled) setError(errorText(e));
    });
    return () => {
      cancelled = true;
    };
  }, [client, system]);
  async function save(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const action_parameters: Record<string, Record<string, unknown>> = {};
      for (const capability of capabilities) {
        if (!words(form.remediation_actions).includes(capability.name))
          continue;
        action_parameters[capability.name] = {};
        for (const [name, type] of Object.entries(capability.parameter_types)) {
          const raw = parameters[capability.name]?.[name] ?? "";
          if (
            type === "number" &&
            (!raw.trim() || !Number.isFinite(Number(raw)))
          )
            throw new Error(`Provide a finite number for ${name}.`);
          action_parameters[capability.name][name] =
            type === "number"
              ? Number(raw)
              : type === "boolean"
                ? raw === "true"
                : raw;
        }
      }
      await client.policy(system.record_id, {
        ...form,
        models: words(form.models),
        tools: words(form.tools),
        resources: words(form.resources),
        actions: words(form.actions),
        remediation_actions: words(form.remediation_actions),
        required_checks: words(form.required_checks),
        trusted_sources: words(form.trusted_sources),
        action_parameters,
      });
      onSaved();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setSaving(false);
    }
  }
  return (
    <details>
      <summary>Draft an operating policy</summary>
      <Stack gap={3}>
        <form onSubmit={save}>
          <Stack gap={3}>
            <Text>
              Set exact operating limits for {system.project} /{" "}
              {system.environment}. Another authorized person must activate this
              draft. A correction can run while quality checks fail, but only
              with its exact preapproved resource, action and parameters.
            </Text>
            {(
              [
                "models",
                "tools",
                "resources",
                "actions",
                "remediation_actions",
                "required_checks",
              ] as const
            ).map((field) => (
              <TextArea
                key={field}
                label={`${field.replaceAll("_", " ")} (one per line)`}
                value={form[field]}
                onChange={(e) => setForm({ ...form, [field]: e.target.value })}
                required={field === "required_checks"}
              />
            ))}
            <Text size="sm">
              Available executor actions:{" "}
              {capabilities.map((c) => c.name).join(", ") || "none registered"}.
            </Text>
            <SelectField
              label="Trusted evidence sources"
              multiple
              required
              options={sources.map((source) => ({
                value: source.record_id,
                label: source.body.name,
              }))}
              value={words(form.trusted_sources)}
              onChange={(e) =>
                setForm({
                  ...form,
                  trusted_sources: Array.from(
                    e.target.selectedOptions,
                    (option) => option.value,
                  ).join("\n"),
                })
              }
            />
            {capabilities
              .filter((c) => words(form.remediation_actions).includes(c.name))
              .map((c) =>
                Object.entries(c.parameter_types).map(([name, type]) =>
                  type === "boolean" ? (
                    <SelectField
                      key={`${c.name}/${name}`}
                      label={`Preapproved ${c.name}: ${name}`}
                      options={[
                        { value: "false", label: "False" },
                        { value: "true", label: "True" },
                      ]}
                      value={parameters[c.name]?.[name] || "false"}
                      onChange={(e) =>
                        setParameters({
                          ...parameters,
                          [c.name]: {
                            ...parameters[c.name],
                            [name]: e.target.value,
                          },
                        })
                      }
                    />
                  ) : (
                    <TextField
                      key={`${c.name}/${name}`}
                      label={`Preapproved ${c.name}: ${name}`}
                      required
                      type={type === "number" ? "number" : "text"}
                      step="any"
                      value={parameters[c.name]?.[name] || ""}
                      onChange={(e) =>
                        setParameters({
                          ...parameters,
                          [c.name]: {
                            ...parameters[c.name],
                            [name]: e.target.value,
                          },
                        })
                      }
                    />
                  ),
                ),
              )}
            <TextField
              label="Maximum autonomy (0–4)"
              type="number"
              min={0}
              max={4}
              value={form.max_autonomy}
              onChange={(e) =>
                setForm({ ...form, max_autonomy: Number(e.target.value) })
              }
            />
            <TextField
              label="Maximum evidence age (seconds)"
              type="number"
              min={60}
              max={2592000}
              value={form.evidence_max_age_seconds}
              onChange={(e) =>
                setForm({
                  ...form,
                  evidence_max_age_seconds: Number(e.target.value),
                })
              }
            />
            <TextField
              label="Permission expiry (seconds)"
              type="number"
              min={1}
              max={300}
              value={form.permit_ttl_seconds}
              onChange={(e) =>
                setForm({ ...form, permit_ttl_seconds: Number(e.target.value) })
              }
            />
            <Checkbox
              label="Require a human checkpoint"
              checked={form.require_human_checkpoint}
              onChange={(e) =>
                setForm({ ...form, require_human_checkpoint: e.target.checked })
              }
            />
            <Checkbox
              label="Allow declared external effects"
              checked={form.allow_external_action}
              onChange={(e) =>
                setForm({ ...form, allow_external_action: e.target.checked })
              }
            />
            <Checkbox
              label="Allow routine releases within these limits without a separate revision reviewer"
              checked={form.allow_routine_releases}
              onChange={(e) =>
                setForm({ ...form, allow_routine_releases: e.target.checked })
              }
            />
            {error ? (
              <Callout tone="danger" title="Configuration request failed">
                {error}
              </Callout>
            ) : null}
            <Button type="submit" disabled={saving}>
              Save policy draft
            </Button>
          </Stack>
        </form>
        <TextField
          label="Import a versioned control pack"
          type="file"
          accept="application/json,.json"
          onChange={async (e) => {
            const input = e.target;
            const file = input.files?.[0];
            if (!file) return;
            setSaving(true);
            try {
              if (file.size > 262144)
                throw new Error("Control packs must be at most 256 KiB.");
              await client.pack(
                { project: system.project, environment: system.environment },
                JSON.parse(await file.text()),
              );
              onSaved();
            } catch (error) {
              setError(errorText(error));
            } finally {
              setSaving(false);
              input.value = "";
            }
          }}
          disabled={saving}
        />
        <Text size="sm">
          Control packs declare applicability, checks, freshness and framework
          references. Import creates a draft for another person to activate. It
          does not certify the organization.
        </Text>
      </Stack>
    </details>
  );
}

const SCOPE_OPTIONS = [
  "systems:read",
  "systems:write",
  "revisions:write",
  "observations:write",
  "authorizations:request",
  "receipts:write",
];
type CapabilityForm = {
  name: string;
  resource_type: string;
  operation: string;
  verification_check: string;
  reversible: boolean;
  parameters: string;
};
export function PortableIntegrationSettings({
  client,
}: {
  client: PortableClient;
}) {
  const [records, setRecords] = useState<PortableRecord[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [form, setForm] = useState({
    name: "",
    namespace: "",
    project: "",
    environment: "",
  });
  const [scopes, setScopes] = useState(["systems:read"]);
  const [capabilities, setCapabilities] = useState<CapabilityForm[]>([]);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let cancelled = false;
    client
      .integrations(undefined, offset)
      .then((result) => {
        if (!cancelled) {
          setRecords(result.integrations);
          setHasMore(result.has_more);
        }
      })
      .catch((e) => {
        if (!cancelled) setError(errorText(e));
      });
    return () => {
      cancelled = true;
    };
  }, [client, refresh, offset]);
  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const declared = capabilities.map(({ parameters, ...capability }) => {
        const entries = words(parameters).map((p) =>
          p.split("=").map((v) => v.trim()),
        );
        if (
          entries.some(
            ([name, type, extra]) =>
              !name ||
              !["string", "number", "boolean"].includes(type) ||
              extra !== undefined,
          ) ||
          new Set(entries.map(([name]) => name)).size !== entries.length
        )
          throw new Error(
            "Each parameter needs a unique name and a type: string, number or boolean.",
          );
        return { ...capability, parameter_types: Object.fromEntries(entries) };
      });
      const result = await client.register({
        ...form,
        scopes,
        capabilities: declared,
      });
      setSecret(result.token);
      setRefresh((v) => v + 1);
      setCapabilities([]);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  async function rotate(record: PortableRecord) {
    if (
      !(await confirm({
        title: "Rotate integration credential",
        body: `Replace ${record.body.name}'s credential immediately. Store and deploy the replacement before resuming requests. System IDs and evidence-source trust stay bound to the same integration.`,
        confirmLabel: "Rotate credential",
      }))
    )
      return;
    setBusy(true);
    try {
      const result = await client.rotate(record.record_id);
      setSecret(result.token);
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  async function revoke(record: PortableRecord) {
    if (
      !(await confirm({
        title: "Revoke integration",
        body: `Stop ${record.body.name} from making new requests. Evidence from this source will no longer establish eligibility.`,
        confirmLabel: "Revoke credential",
        tone: "danger",
      }))
    )
      return;
    setBusy(true);
    try {
      await client.revoke(record.record_id);
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Section
      title="Execution and evidence integrations"
      description="Separate scoped credentials for executors and evidence sources; no authority to approve their own governance decisions."
    >
      <Stack gap={3}>
        {secret ? (
          <SecretReveal
            label="Integration credential"
            value={secret}
            onDismiss={() => setSecret("")}
          />
        ) : null}
        {error ? (
          <Callout tone="danger" title="Integration request failed">
            {error}
          </Callout>
        ) : null}
        {records.map((record) => (
          <Card key={record.record_id} padding="md">
            <Inline gap={2}>
              <Text>
                {record.body.name} · {record.project} / {record.environment}
              </Text>
              <Badge value={record.state}>{portableStatusLabel(record.state)}</Badge>
              {record.state === "active" ? (
                <>
                  <Button
                    variant="secondary"
                    disabled={busy || !!secret}
                    onClick={() => void rotate(record)}
                  >
                    Rotate {record.body.name}
                  </Button>
                  <Button
                    variant="danger"
                    disabled={busy}
                    onClick={() => void revoke(record)}
                  >
                    Revoke {record.body.name}
                  </Button>
                </>
              ) : null}
            </Inline>
            <Text size="sm">{record.body.scopes.join(", ")}</Text>
          </Card>
        ))}
        <Inline gap={2}>
          <Button
            variant="secondary"
            disabled={offset === 0}
            onClick={() => setOffset((v) => Math.max(0, v - 100))}
          >
            Previous integrations
          </Button>
          <Button
            variant="secondary"
            disabled={!hasMore}
            onClick={() => setOffset((v) => v + 100)}
          >
            Next integrations
          </Button>
        </Inline>
        <details>
          <summary>Connect an executor or evidence source</summary>
          <form onSubmit={save}>
            <Stack gap={3}>
              <Text>
                Use a separate credential for the collector that verifies an
                executor's correction. Keep credentials in the server's secret
                store.
              </Text>
              {(["name", "namespace", "project", "environment"] as const).map(
                (field) => (
                  <TextField
                    key={field}
                    label={field}
                    required
                    maxLength={128}
                    value={form[field]}
                    onChange={(e) =>
                      setForm({ ...form, [field]: e.target.value })
                    }
                    pattern={
                      field === "namespace" ? "[a-z][a-z0-9_.-]*" : undefined
                    }
                  />
                ),
              )}
              {SCOPE_OPTIONS.map((scope) => (
                <Checkbox
                  key={scope}
                  label={scope}
                  checked={scopes.includes(scope)}
                  onChange={(e) =>
                    setScopes(
                      e.target.checked
                        ? [...scopes, scope]
                        : scopes.filter((s) => s !== scope),
                    )
                  }
                />
              ))}
              {capabilities.map((capability, index) => (
                <fieldset key={index}>
                  <legend>Action {index + 1}</legend>
                  {(
                    [
                      "name",
                      "resource_type",
                      "operation",
                      "verification_check",
                      "parameters",
                    ] as const
                  ).map((field) => (
                    <TextField
                      key={field}
                      label={
                        field === "parameters"
                          ? "Parameters (comma-separated name=string, name=number or name=boolean)"
                          : field.replaceAll("_", " ")
                      }
                      required={field !== "parameters"}
                      value={capability[field]}
                      onChange={(e) =>
                        setCapabilities(
                          capabilities.map((c, i) =>
                            i === index ? { ...c, [field]: e.target.value } : c,
                          ),
                        )
                      }
                    />
                  ))}
                  <Checkbox
                    label="This action can be reversed"
                    checked={capability.reversible}
                    onChange={(e) =>
                      setCapabilities(
                        capabilities.map((c, i) =>
                          i === index
                            ? { ...c, reversible: e.target.checked }
                            : c,
                        ),
                      )
                    }
                  />
                  <Button
                    variant="secondary"
                    onClick={() =>
                      setCapabilities(
                        capabilities.filter((_, i) => i !== index),
                      )
                    }
                  >
                    Remove action {index + 1}
                  </Button>
                </fieldset>
              ))}
              <Button
                variant="secondary"
                disabled={capabilities.length >= 32}
                onClick={() =>
                  setCapabilities([
                    ...capabilities,
                    {
                      name: "",
                      resource_type: "",
                      operation: "",
                      verification_check: "",
                      parameters: "",
                      reversible: false,
                    },
                  ])
                }
              >
                Declare an executor action
              </Button>
              <Text size="sm">
                Declaring an action grants no permission until an independently
                activated operating policy allows it.
              </Text>
              <Button
                type="submit"
                disabled={busy || !scopes.length || !!secret}
              >
                Issue scoped integration credential
              </Button>
            </Stack>
          </form>
        </details>
      </Stack>
    </Section>
  );
}

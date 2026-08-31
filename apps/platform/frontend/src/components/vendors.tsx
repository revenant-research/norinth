// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useState } from "react";

import { getJson, postJson } from "../api";
import { confirm } from "./confirm";
import { toast } from "./toast";
import { type ApprovalStage, StageWorkflow } from "./stages";
import { Badge, Chip, EmptyState, MetricCard, RecordList, Section } from "./ui";
import { formatTimestamp } from "./table";
import { useResource } from "./useResource";

// the vendor registry, joined to what production telemetry actually shows.
// posture is proven by observed provider usage, not a spreadsheet: a provider
// with no approved vendor entry is a live risk finding

type Vendor = {
  vendor_id: string;
  name: string;
  status: string;
  providers: string[];
  approved_models: string[] | null;
  review_round: number;
  reviewed_at?: string | null;
  stages: ApprovalStage[];
};

type Coverage = {
  providers: Array<{
    provider: string;
    models: string[];
    applications: string[];
    vendor: string | null;
    vendor_status: string | null;
    covered: boolean;
    disallowed_models: string[];
  }>;
  summary: { observed_providers: number; covered: number; uncovered: number; registered_vendors: number };
};

type VendorsPayload = {
  vendors: Vendor[];
  coverage: Coverage;
  policy: { stages: Array<{ role: string; label?: string }>; recertify_days?: number | null };
};

export const STATUS_HELP: Record<string, string> = {
  draft: "Not yet reviewed; its providers count as unreviewed",
  under_review: "Approval stages in progress",
  approved: "Reviewed and approved; its providers are covered",
  rejected: "Rejected; its providers count as unreviewed",
  recertify_due: "Approval lapsed; re-review to restore coverage",
  retired: "No longer sanctioned",
};

const EMPTY_FORM = { name: "", providers: "", approved_models: "" };

export function splitList(text: string): string[] {
  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function VendorsView({ canManage, canRetire }: { canManage: boolean; canRetire: boolean }) {
  const registry = useResource(() => getJson<VendorsPayload>("/api/vendors"));
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [submitting, setSubmitting] = useState(false);

  const summary = registry.value?.coverage.summary;
  const observed = registry.value?.coverage.providers || [];
  const vendors = registry.value?.vendors || [];
  const policy = registry.value?.policy;

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await postJson("/api/vendors", {
        name: form.name,
        providers: splitList(form.providers),
        approved_models: form.approved_models.trim() ? splitList(form.approved_models) : null,
      });
      toast.success(`Vendor "${form.name}" saved. Submit it for review to make it count.`);
      setForm({ ...EMPTY_FORM });
      registry.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not save the vendor.");
    } finally {
      setSubmitting(false);
    }
  }

  async function submitForReview(vendor: Vendor) {
    const stageCount = policy?.stages?.length || 1;
    const ok = await confirm({
      title: `Submit ${vendor.name} for review?`,
      body: `The governance policy requires ${stageCount} approval stage${stageCount === 1 ? "" : "s"}. You are the submitter, so you cannot decide any of them yourself.`,
      confirmLabel: "Submit for review",
    });
    if (!ok) return;
    try {
      await postJson(`/api/vendors/${encodeURIComponent(vendor.vendor_id)}/submit-review`, {});
      toast.success(`${vendor.name} is under review.`);
      registry.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not start the review.");
    }
  }

  async function retire(vendor: Vendor) {
    const ok = await confirm({
      title: `Retire ${vendor.name}?`,
      body: "Its providers will count as unreviewed again if they keep appearing in telemetry.",
      confirmLabel: "Retire vendor",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await postJson(`/api/vendors/${encodeURIComponent(vendor.vendor_id)}/retire`, {});
      toast.success(`${vendor.name} retired.`);
      registry.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not retire the vendor.");
    }
  }

  return (
    <>
      {registry.error ? <p className="feedback error" role="alert">{registry.error}</p> : null}
      <div className="metric-grid">
        <MetricCard label="Providers in production" value={summary?.observed_providers ?? "–"} note="Seen in model-call telemetry" />
        <MetricCard label="Covered" value={summary?.covered ?? "–"} note="Backed by an approved vendor" />
        <MetricCard label="Unreviewed" value={summary?.uncovered ?? "–"} note="Raising RISK-VND-001 findings" />
        <MetricCard label="Registered vendors" value={summary?.registered_vendors ?? "–"} note="In the registry" />
      </div>

      <Section
        title="Observed in production"
        description="Every model provider your telemetry names, reconciled against the registry. Coverage is proven by production, not by a spreadsheet."
      >
        <RecordList empty="No provider usage observed yet. Providers appear here as soon as model-call telemetry arrives.">
          {observed.map((row) => (
            <article className="record-card" key={row.provider} data-testid="provider-card">
              <div className="record-main">
                <span className="record-title">{row.provider}</span>
                <Badge value={row.covered ? "covered" : "unreviewed"} />
                {row.vendor ? <Chip>{row.vendor} · {row.vendor_status}</Chip> : null}
              </div>
              <p>
                Models: {row.models.join(", ") || "unknown"} · used by {row.applications.join(", ")}
              </p>
              {row.disallowed_models.length ? (
                <p className="feedback error" role="alert">
                  Outside the approved model list: {row.disallowed_models.join(", ")}
                </p>
              ) : null}
              {!row.covered && canManage && !row.vendor ? (
                <div className="flag-action">
                  <button type="button" onClick={() => setForm({ name: row.provider, providers: row.provider, approved_models: "" })}>
                    Register {row.provider} as a vendor
                  </button>
                </div>
              ) : null}
            </article>
          ))}
        </RecordList>
      </Section>

      {canManage ? (
        <Section
          title="Register a vendor"
          description="Name the vendor and the provider strings your telemetry reports for it. An optional model allow-list flags any other model from that provider."
        >
          <form className="admin-form" onSubmit={save} aria-label="Register a vendor">
            <label>
              Vendor name
              <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required placeholder="OpenAI" />
            </label>
            <label>
              Providers (comma-separated)
              <input value={form.providers} onChange={(event) => setForm({ ...form, providers: event.target.value })} required placeholder="openai" />
            </label>
            <label className="wide">
              Approved models (optional, comma-separated)
              <input
                value={form.approved_models}
                onChange={(event) => setForm({ ...form, approved_models: event.target.value })}
                placeholder="leave empty to allow any model from these providers"
              />
            </label>
            <button type="submit" disabled={submitting}>
              {submitting ? "Saving…" : "Save vendor"}
            </button>
          </form>
        </Section>
      ) : null}

      <Section
        title="Vendor registry"
        description="Each vendor is approved through the policy's review stages and recertified on the policy's clock. Editing an approved vendor's providers or models sends it back to draft."
      >
        {vendors.length === 0 ? (
          <EmptyState>No vendors registered yet. Register the providers you see in production above.</EmptyState>
        ) : (
          <RecordList empty="">
            {vendors.map((vendor) => (
              <article className="record-card" key={vendor.vendor_id} data-testid="vendor-card">
                <div className="record-main">
                  <span className="record-title">{vendor.name}</span>
                  <Badge value={vendor.status} />
                  {vendor.review_round > 0 ? <Chip>review round {vendor.review_round}</Chip> : null}
                </div>
                <p className="muted">{STATUS_HELP[vendor.status] || vendor.status}</p>
                <p>
                  Providers: {vendor.providers.join(", ")} · models:{" "}
                  {vendor.approved_models ? vendor.approved_models.join(", ") : "any"}
                  {vendor.reviewed_at ? ` · last reviewed ${formatTimestamp(vendor.reviewed_at)}` : ""}
                </p>
                {vendor.status === "under_review" ? (
                  <StageWorkflow stages={vendor.stages} subjectLabel={`vendor ${vendor.name}`} onDecided={registry.reload} />
                ) : null}
                <div className="inline-form">
                  {canManage && ["draft", "rejected", "approved", "recertify_due"].includes(vendor.status) ? (
                    <button type="button" className="secondary" onClick={() => submitForReview(vendor)}>
                      {vendor.status === "draft" || vendor.status === "rejected" ? "Submit for review" : "Re-review"}
                    </button>
                  ) : null}
                  {canRetire && vendor.status !== "retired" ? (
                    <button type="button" className="secondary" onClick={() => retire(vendor)}>
                      Retire
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </RecordList>
        )}
      </Section>
    </>
  );
}

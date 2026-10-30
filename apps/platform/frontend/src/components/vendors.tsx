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

// a dated reference to a vendor document: never the document itself
export type EvidenceReference = {
  reference_id: string;
  kind: string;
  kind_label: string;
  name: string;
  identifier: string | null;
  issued_at: string;
  expires_at: string;
  document_hash: string | null;
  status: string;
};

type Vendor = {
  vendor_id: string;
  name: string;
  status: string;
  providers: string[];
  approved_models: string[] | null;
  review_round: number;
  reviewed_at?: string | null;
  stages: ApprovalStage[];
  evidence: EvidenceReference[];
  evidence_expired: boolean;
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
  evidence_kinds: Record<string, string>;
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

export const EVIDENCE_STATUS_HELP: Record<string, string> = {
  current: "In force",
  expired: "Lapsed; the vendor cannot be approved until it is replaced or withdrawn",
  superseded: "Replaced by a newer reference of the same kind",
  withdrawn: "Withdrawn",
};

const EMPTY_EVIDENCE = { kind: "baa", name: "", identifier: "", issued_at: "", expires_at: "", document_hash: "" };

export function daysUntil(isoDate: string, today: Date = new Date()): number {
  const target = new Date(`${isoDate}T00:00:00Z`);
  const start = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  return Math.round((target.getTime() - start) / 86_400_000);
}

function EvidenceForm({ vendor, kinds, onRecorded }: { vendor: Vendor; kinds: Record<string, string>; onRecorded: () => void }) {
  const [form, setForm] = useState({ ...EMPTY_EVIDENCE });
  const [saving, setSaving] = useState(false);

  async function record(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await postJson(`/api/vendors/${encodeURIComponent(vendor.vendor_id)}/evidence`, {
        kind: form.kind,
        name: form.name,
        identifier: form.identifier.trim() || null,
        issued_at: form.issued_at,
        expires_at: form.expires_at,
        document_hash: form.document_hash.trim() || null,
      });
      toast.success(`${kinds[form.kind] || form.kind} recorded for ${vendor.name}.`);
      setForm({ ...EMPTY_EVIDENCE });
      onRecorded();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not record the reference.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="admin-form" onSubmit={record} aria-label={`Record evidence for ${vendor.name}`}>
      <label>
        Kind
        <select value={form.kind} onChange={(event) => setForm({ ...form, kind: event.target.value })}>
          {Object.entries(kinds).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Name
        <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required placeholder="BAA 2026" />
      </label>
      <label>
        Reference number (optional)
        <input value={form.identifier} onChange={(event) => setForm({ ...form, identifier: event.target.value })} placeholder="BAA-77" />
      </label>
      <label>
        Issued
        <input type="date" value={form.issued_at} onChange={(event) => setForm({ ...form, issued_at: event.target.value })} required />
      </label>
      <label>
        Expires
        <input type="date" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} required />
      </label>
      <label className="wide">
        Document SHA-256 (optional; the document itself is never uploaded)
        <input
          value={form.document_hash}
          onChange={(event) => setForm({ ...form, document_hash: event.target.value })}
          placeholder="64 hex characters"
          pattern="[0-9a-fA-F]{64}"
        />
      </label>
      <button type="submit" disabled={saving}>
        {saving ? "Recording…" : "Record reference"}
      </button>
    </form>
  );
}

function EvidenceList({ vendor, canManage, onChanged }: { vendor: Vendor; canManage: boolean; onChanged: () => void }) {
  async function withdraw(reference: EvidenceReference) {
    const ok = await confirm({
      title: `Withdraw ${reference.kind_label} "${reference.name}"?`,
      body: "Withdraw a reference recorded in error or revoked by the vendor. The audit log keeps the record.",
      confirmLabel: "Withdraw",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await postJson(
        `/api/vendors/${encodeURIComponent(vendor.vendor_id)}/evidence/${encodeURIComponent(reference.reference_id)}/withdraw`,
        {},
      );
      toast.success("Reference withdrawn.");
      onChanged();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not withdraw the reference.");
    }
  }

  const visible = vendor.evidence.filter((item) => item.status !== "withdrawn" && item.status !== "superseded");
  if (visible.length === 0) {
    return <p className="muted">No evidence references recorded. Record the agreements and certificates this vendor's approval rests on.</p>;
  }
  return (
    <ul className="evidence-list" aria-label={`Evidence for ${vendor.name}`}>
      {visible.map((item) => {
        const remaining = daysUntil(item.expires_at);
        return (
          <li key={item.reference_id} data-testid="evidence-row">
            <span className="record-title">{item.kind_label}</span> {item.name}
            {item.identifier ? ` (${item.identifier})` : ""} · issued {item.issued_at} · expires {item.expires_at}
            {item.status === "current" && remaining <= 30 ? <Chip>expires in {remaining} day{remaining === 1 ? "" : "s"}</Chip> : null}
            <Badge value={item.status} />
            {item.status === "expired" ? (
              <p className="feedback error" role="alert">
                {EVIDENCE_STATUS_HELP.expired}
              </p>
            ) : null}
            {canManage && item.status !== "withdrawn" ? (
              <button type="button" className="secondary" onClick={() => withdraw(item)}>
                Withdraw
              </button>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

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
  const evidenceKinds = registry.value?.evidence_kinds || {};

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
        description="Each vendor is approved through the policy's review stages and recertified on the policy's clock. Its agreements and certificates are recorded as dated references, never as documents; an expired reference lapses the approval until it is renewed."
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
                {vendor.evidence_expired ? (
                  <p className="feedback error" role="alert">
                    Evidence has expired. Record a current reference or withdraw the expired one before re-review.
                  </p>
                ) : null}
                <p>
                  Providers: {vendor.providers.join(", ")} · models:{" "}
                  {vendor.approved_models ? vendor.approved_models.join(", ") : "any"}
                  {vendor.reviewed_at ? ` · last reviewed ${formatTimestamp(vendor.reviewed_at)}` : ""}
                </p>
                {vendor.status === "under_review" ? (
                  <StageWorkflow stages={vendor.stages} subjectLabel={`vendor ${vendor.name}`} onDecided={registry.reload} />
                ) : null}
                <EvidenceList vendor={vendor} canManage={canManage} onChanged={registry.reload} />
                {canManage && vendor.status !== "retired" ? (
                  <details>
                    <summary>Record an evidence reference</summary>
                    <EvidenceForm vendor={vendor} kinds={evidenceKinds} onRecorded={registry.reload} />
                  </details>
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

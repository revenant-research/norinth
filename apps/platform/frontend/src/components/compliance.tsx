import { useState } from "react";

import { type Scope, getJson } from "../api";
import { toast } from "./toast";
import { Badge, EmptyState, MetricCard, Section } from "./ui";
import { useResource } from "./useResource";

// per-framework coverage and the audit-evidence packet. coverage shows, for
// each standard the control library cites, how many mapped requirements are
// satisfied by passing or waived evidence and which are still outstanding
// the packet is downloaded as json from the browser

export type FrameworkCoverage = {
  framework: string;
  total_requirements: number;
  satisfied: number;
  coverage_pct: number;
  gaps: string[];
  satisfied_requirements: string[];
};

export function coverageTone(pct: number): "good" | "mid" | "low" {
  if (pct >= 80) return "good";
  if (pct >= 50) return "mid";
  return "low";
}

export function CoverageBar({ pct }: { pct: number }) {
  return (
    <div className="coverage-bar" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={`${pct}% coverage`}>
      <div className={`coverage-fill ${coverageTone(pct)}`} style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
    </div>
  );
}

export function FrameworkCoverageCards({ rows }: { rows: FrameworkCoverage[] }) {
  const [open, setOpen] = useState<string | null>(null);
  if (rows.length === 0) {
    return <EmptyState>No framework-mapped control assessments yet. Coverage appears once telemetry produces control evidence.</EmptyState>;
  }
  return (
    <div className="record-list">
      {rows.map((row) => {
        const expanded = open === row.framework;
        return (
          <article className="record-card" key={row.framework} data-testid="framework-card">
            <div className="record-main">
              <span className="record-title">{row.framework}</span>
              <Badge value={`${row.coverage_pct}%`} />
              <span className="muted">
                {row.satisfied} of {row.total_requirements} requirements satisfied
              </span>
            </div>
            <CoverageBar pct={row.coverage_pct} />
            {row.gaps.length ? (
              <>
                <button type="button" className="linklike" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : row.framework)}>
                  {expanded ? "Hide" : "Show"} {row.gaps.length} outstanding requirement{row.gaps.length === 1 ? "" : "s"}
                </button>
                {expanded ? (
                  <ul className="gap-list" aria-label={`Outstanding requirements for ${row.framework}`}>
                    {row.gaps.map((gap) => (
                      <li key={gap}>
                        <code>{gap}</code>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </>
            ) : (
              <p className="ok">All mapped requirements have evidence.</p>
            )}
          </article>
        );
      })}
    </div>
  );
}

export function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function ComplianceView({ scope, tenantId }: { scope: Scope; tenantId: string }) {
  const coverage = useResource(() => getJson<{ framework_coverage: FrameworkCoverage[] }>("/api/compliance/framework-coverage", scope));
  const [downloading, setDownloading] = useState(false);
  const [lastPacket, setLastPacket] = useState<{ generated_at: string; integrity_ok: boolean; risk_findings: number; control_assessments: number } | null>(null);

  const rows = coverage.value?.framework_coverage || [];
  const overall = rows.length ? Math.round(rows.reduce((sum, row) => sum + row.coverage_pct, 0) / rows.length) : 0;
  const totalGaps = rows.reduce((sum, row) => sum + row.gaps.length, 0);

  async function exportPacket() {
    setDownloading(true);
    try {
      const packet = await getJson<Record<string, any>>("/api/compliance/audit-packet", scope);
      const stamp = String(packet.generated_at || "").replace(/[:.]/g, "-").slice(0, 19) || "now";
      downloadJson(`norinth-audit-packet-${tenantId}-${stamp}.json`, packet);
      setLastPacket({
        generated_at: packet.generated_at,
        integrity_ok: !!packet.audit_trail?.integrity?.ok,
        risk_findings: (packet.risk_findings || []).length,
        control_assessments: (packet.control_assessments || []).length,
      });
      toast.success("Audit packet downloaded.");
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not build the audit packet.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <>
      {coverage.error ? <p className="feedback error" role="alert">{coverage.error}</p> : null}
      <div className="metric-grid">
        <MetricCard label="Frameworks" value={rows.length} note="Cited by the control library" />
        <MetricCard label="Average coverage" value={rows.length ? `${overall}%` : "–"} note="Requirements with evidence" />
        <MetricCard label="Outstanding" value={totalGaps} note="Requirements without evidence" />
        <MetricCard label="Audit trail" value={lastPacket ? (lastPacket.integrity_ok ? "verified" : "BROKEN") : "–"} note={lastPacket ? `Checked at export ${lastPacket.generated_at}` : "Verified when you export a packet"} />
      </div>

      <Section title="Framework coverage" description="For every regulation or standard the control library cites: how many mapped requirements are satisfied by passing or waived evidence, and which are still outstanding.">
        <FrameworkCoverageCards rows={rows} />
      </Section>

      <Section title="Audit-evidence packet" description="One self-contained export for an auditor or certification body: inventory, framework coverage, control assessments, risk findings, decisions and exceptions, release gates, incidents, material changes, agent posture, the CycloneDX AI-BOM, and a tamper-evidence check of the audit trail.">
        <div className="form-actions">
          <button type="button" onClick={exportPacket} disabled={downloading} data-testid="export-packet">
            {downloading ? "Assembling…" : "Export audit packet (JSON)"}
          </button>
        </div>
        {lastPacket ? (
          <dl className="kv" data-testid="packet-summary">
            <dt>Generated</dt>
            <dd>{lastPacket.generated_at}</dd>
            <dt>Audit-trail integrity</dt>
            <dd>
              <Badge value={lastPacket.integrity_ok ? "verified" : "broken"} />
            </dd>
            <dt>Control assessments</dt>
            <dd>{lastPacket.control_assessments}</dd>
            <dt>Risk findings</dt>
            <dd>{lastPacket.risk_findings}</dd>
          </dl>
        ) : null}
      </Section>
    </>
  );
}

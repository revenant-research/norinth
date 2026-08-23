import { useEffect, useState, type ReactNode } from "react";

export function Badge({ value }: { value: ReactNode }) {
  return <span className={`badge badge-${String(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]/g, "_")}`}>{value || "unknown"}</span>;
}

export function Chip({ children }: { children: ReactNode }) {
  return <span className="chip">{children}</span>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

export function MetricCard({ label, value, note }: { label: string; value: ReactNode; note?: string }) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {note ? <div className="metric-note">{note}</div> : null}
    </div>
  );
}

export function Section({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <section className="section">
      <div className="section-header">
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {children}
    </section>
  );
}

export const RECORD_LIST_PAGE_SIZE = 25;

/**
 * Renders a bounded window of records with a "Show more" control instead of
 * mounting every card at once (the audit flagged unbounded lists melting the
 * DOM on large tenants). `total` is the server-side total when the caller only
 * holds the first page, so the footer can say how many records exist overall.
 */
export function RecordList({
  children,
  empty,
  pageSize = RECORD_LIST_PAGE_SIZE,
  total,
  label = "records",
}: {
  children: ReactNode[];
  empty: string;
  pageSize?: number;
  total?: number;
  label?: string;
}) {
  const [visible, setVisible] = useState(pageSize);
  // A new result set (filter change, refresh) resets the window.
  useEffect(() => setVisible(pageSize), [children.length, pageSize]);
  if (!children.length) return <EmptyState>{empty}</EmptyState>;
  const shown = children.slice(0, visible);
  const loaded = children.length;
  const overall = typeof total === "number" && total > loaded ? total : loaded;
  const hasMore = visible < loaded;
  return (
    <div className="record-list-wrap">
      <div className="record-list">{shown}</div>
      {hasMore || overall > loaded ? (
        <div className="record-list-footer" role="status" aria-live="polite">
          <span className="muted">
            Showing {Math.min(visible, loaded)} of {overall} {label}
            {overall > loaded ? ` (${loaded} loaded)` : ""}
          </span>
          {hasMore ? (
            <button type="button" className="secondary" onClick={() => setVisible((v) => v + pageSize)}>
              Show {Math.min(pageSize, loaded - visible)} more
            </button>
          ) : null}
          {hasMore && loaded - visible > pageSize ? (
            <button type="button" className="linklike" onClick={() => setVisible(loaded)}>
              Show all {loaded}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function formatList(values: unknown): string {
  return Array.isArray(values) && values.length ? values.join(", ") : "";
}

export function Skeleton({ width = "100%", height = 14 }: { width?: string; height?: number }) {
  return <span className="skeleton" style={{ width, height }} aria-hidden="true" />;
}

export function SkeletonMetrics({ count = 4 }: { count?: number }) {
  return (
    <div className="metric-grid" aria-hidden="true">
      {Array.from({ length: count }).map((_, index) => (
        <div className="metric-card" key={index}>
          <Skeleton width="50%" height={12} />
          <div style={{ marginTop: 8 }}>
            <Skeleton width="35%" height={26} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function SkeletonCards({ count = 3 }: { count?: number }) {
  return (
    <div className="record-list" aria-hidden="true">
      {Array.from({ length: count }).map((_, index) => (
        <div className="record-card skeleton-card" key={index}>
          <Skeleton width="40%" height={14} />
          <div style={{ marginTop: 10 }}>
            <Skeleton width="70%" height={12} />
          </div>
        </div>
      ))}
    </div>
  );
}

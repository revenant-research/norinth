import type { ReactNode } from "react";

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

export function RecordList({ children, empty }: { children: ReactNode[]; empty: string }) {
  return children.length ? <div className="record-list">{children}</div> : <EmptyState>{empty}</EmptyState>;
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

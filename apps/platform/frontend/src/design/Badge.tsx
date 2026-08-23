import type { ReactNode } from "react";

import styles from "./Badge.module.css";

export type Tone = "neutral" | "signal" | "success" | "warning" | "danger";

const STATUS_TONES: Record<string, Tone> = {
  approved: "success", passing: "success", success: "success", closed: "success", active: "success", attested: "success",
  resolved: "success", assigned: "success", linked: "success", registered: "success", enforced: "success", healthy: "success",
  open: "warning", pending: "warning", pending_review: "warning", unassigned: "warning", unattested: "warning", medium: "warning",
  in_review: "warning", waived: "warning", accepted: "warning", mitigated: "warning", stale: "warning", suspended: "warning",
  rejected: "danger", missing: "danger", error: "danger", failed: "danger", high: "danger", critical: "danger", revoked: "danger",
  blocked: "danger", unregistered: "danger", overdue: "danger",
  low: "neutral", info: "neutral", observe: "neutral", unknown: "neutral", platform: "neutral",
};

/** Map a free-form status string to a tone. Unknown statuses are neutral. */
export function statusTone(status: unknown): Tone {
  return STATUS_TONES[String(status ?? "").toLowerCase()] ?? "neutral";
}

export function Badge({ children, tone, value }: { children?: ReactNode; tone?: Tone; value?: unknown }) {
  const label = children ?? (value === undefined || value === null || value === "" ? "unknown" : String(value));
  const resolved = tone ?? statusTone(value ?? (typeof children === "string" ? children : undefined));
  return <span className={[styles.badge, styles[resolved]].join(" ")}>{label}</span>;
}

export function Chip({ children }: { children: ReactNode }) {
  return <span className={styles.chip}>{children}</span>;
}

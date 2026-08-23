import type { ReactNode } from "react";

import styles from "./Stat.module.css";

/** label-over-number block, e.g. "JOBS / 32" */
export function Stat({ label, value, note, tone = "ink" }: { label: string; value: ReactNode; note?: ReactNode; tone?: "ink" | "signal" | "warning" | "danger" }) {
  return (
    <div className={styles.stat}>
      <dt className={styles.label}>{label}</dt>
      <dd className={[styles.value, styles[`tone_${tone}`]].join(" ")}>{value}</dd>
      {note ? <dd className={styles.note}>{note}</dd> : null}
    </div>
  );
}

/** row of Stats; renders a definition list so label/value pairs are semantic */
export function StatGroup({ children, columns }: { children: ReactNode; columns?: number }) {
  return (
    <dl className={styles.group} style={columns ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` } : undefined}>
      {children}
    </dl>
  );
}

import type { ReactNode } from "react";

import styles from "./Feedback.module.css";

/** Inline message block. `tone` picks colour and the ARIA role. */
export function Callout({ tone = "info", title, children, action }: { tone?: "info" | "success" | "warning" | "danger"; title?: ReactNode; children: ReactNode; action?: ReactNode }) {
  const role = tone === "danger" || tone === "warning" ? "alert" : "status";
  return (
    <div className={[styles.callout, styles[tone]].join(" ")} role={role}>
      <div className={styles.body}>
        {title ? <strong className={styles.title}>{title}</strong> : null}
        <div>{children}</div>
      </div>
      {action ? <div className={styles.action}>{action}</div> : null}
    </div>
  );
}

export function EmptyState({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className={styles.empty}>
      <div>{children}</div>
      {action ? <div className={styles.action}>{action}</div> : null}
    </div>
  );
}

export function CodeBlock({ children, label }: { children: string; label?: string }) {
  return (
    <pre className={styles.code} aria-label={label}>
      <code>{children}</code>
    </pre>
  );
}

export function Skeleton({ width = "100%", height = 14 }: { width?: string; height?: number }) {
  return <span className={styles.skeleton} style={{ width, height }} aria-hidden="true" />;
}

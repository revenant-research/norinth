import type { HTMLAttributes, ReactNode } from "react";

import styles from "./Card.module.css";

/**
 * Paper card with an ink rule — the Revenant surface. `tone="lead"` is the
 * featured variant (used for the hero card on the landing page); `interactive`
 * adds hover affordance for clickable cards.
 */
export function Card({
  children,
  padding = "md",
  tone = "paper",
  interactive = false,
  className,
  as: Tag = "div",
  ...rest
}: {
  children: ReactNode;
  padding?: "none" | "sm" | "md" | "lg";
  tone?: "paper" | "lead" | "well";
  interactive?: boolean;
  as?: "div" | "article" | "section" | "a" | "li";
} & HTMLAttributes<HTMLElement>) {
  const cls = [styles.card, styles[`pad_${padding}`], styles[`tone_${tone}`], interactive && styles.interactive, className]
    .filter(Boolean)
    .join(" ");
  return (
    <Tag className={cls} {...(rest as object)}>
      {children}
    </Tag>
  );
}

export function CardHeader({ children, className, ...rest }: { children: ReactNode } & HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={[styles.header, className].filter(Boolean).join(" ")} {...rest}>
      {children}
    </div>
  );
}

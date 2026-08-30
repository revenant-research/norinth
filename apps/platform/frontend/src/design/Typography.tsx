// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import type { ElementType, HTMLAttributes, ReactNode } from "react";

import styles from "./Typography.module.css";

function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/** uppercase, letter-spaced label in the signal colour */
export function Eyebrow({ children, tone = "signal", className, ...rest }: { children: ReactNode; tone?: "signal" | "dim" | "inverse" } & HTMLAttributes<HTMLSpanElement>) {
  return (
    <span className={cx(styles.eyebrow, tone === "dim" && styles.eyebrowDim, tone === "inverse" && styles.eyebrowInverse, className)} {...rest}>
      {children}
    </span>
  );
}

export function Heading({
  level = 2,
  size,
  children,
  className,
  ...rest
}: { level?: 1 | 2 | 3 | 4; size?: "3xl" | "2xl" | "xl" | "lg"; children: ReactNode } & HTMLAttributes<HTMLHeadingElement>) {
  const Tag = `h${level}` as ElementType;
  const resolved = size ?? (level === 1 ? "3xl" : level === 2 ? "2xl" : level === 3 ? "xl" : "lg");
  return (
    <Tag className={cx(styles.heading, styles[`h_${resolved}`], className)} {...rest}>
      {children}
    </Tag>
  );
}

export function Text({
  as: Tag = "p",
  tone = "dim",
  size = "md",
  children,
  className,
  ...rest
}: { as?: ElementType; tone?: "ink" | "muted" | "dim"; size?: "xs" | "sm" | "md" | "lg"; children: ReactNode } & HTMLAttributes<HTMLElement>) {
  return (
    <Tag className={cx(styles.text, styles[`tone_${tone}`], styles[`size_${size}`], className)} {...rest}>
      {children}
    </Tag>
  );
}

/** lead paragraph under a heading */
export function Lede({ children, className, ...rest }: { children: ReactNode } & HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p className={cx(styles.lede, className)} {...rest}>
      {children}
    </p>
  );
}

export function Code({ children, className, ...rest }: { children: ReactNode } & HTMLAttributes<HTMLElement>) {
  return (
    <code className={cx(styles.code, className)} {...rest}>
      {children}
    </code>
  );
}

import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

import styles from "./Button.module.css";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "link";
type Size = "sm" | "md" | "lg";

function cls(variant: Variant, size: Size, extra?: string): string {
  return [styles.button, styles[variant], styles[size], extra].filter(Boolean).join(" ");
}

export function Button({
  variant = "primary",
  size = "md",
  className,
  type = "button",
  children,
  ...rest
}: { variant?: Variant; size?: Size; children: ReactNode } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type={type} className={cls(variant, size, className)} {...rest}>
      {children}
    </button>
  );
}

/** same visual language as Button, for navigation */
export function ButtonLink({
  variant = "primary",
  size = "md",
  className,
  children,
  ...rest
}: { variant?: Variant; size?: Size; children: ReactNode } & AnchorHTMLAttributes<HTMLAnchorElement>) {
  return (
    <a className={cls(variant, size, className)} {...rest}>
      {children}
    </a>
  );
}

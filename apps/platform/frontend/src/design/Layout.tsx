import type { CSSProperties, ElementType, HTMLAttributes, ReactNode } from "react";

import styles from "./Layout.module.css";

type Gap = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;

function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/** Vertical rhythm. */
export function Stack({ gap = 4, as: Tag = "div", children, className, ...rest }: { gap?: Gap; as?: ElementType; children: ReactNode } & HTMLAttributes<HTMLElement>) {
  return (
    <Tag className={cx(styles.stack, styles[`gap_${gap}`], className)} {...rest}>
      {children}
    </Tag>
  );
}

/** Horizontal row that wraps. */
export function Inline({ gap = 2, align = "center", justify = "start", as: Tag = "div", children, className, ...rest }: { gap?: Gap; align?: "start" | "center" | "end" | "baseline"; justify?: "start" | "between" | "end"; as?: ElementType; children: ReactNode } & HTMLAttributes<HTMLElement>) {
  return (
    <Tag className={cx(styles.inline, styles[`gap_${gap}`], styles[`align_${align}`], styles[`justify_${justify}`], className)} {...rest}>
      {children}
    </Tag>
  );
}

/** Responsive grid: `min` is the minimum column width. */
export function Grid({ min = "260px", gap = 4, columns, children, className, ...rest }: { min?: string; gap?: Gap; columns?: number; children: ReactNode } & HTMLAttributes<HTMLDivElement>) {
  const style: CSSProperties = columns
    ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }
    : { gridTemplateColumns: `repeat(auto-fit, minmax(min(${min}, 100%), 1fr))` };
  return (
    <div className={cx(styles.grid, styles[`gap_${gap}`], className)} style={style} {...rest}>
      {children}
    </div>
  );
}

/** Centred content column with the site's horizontal padding. */
export function Container({ children, className, wide = false, ...rest }: { children: ReactNode; wide?: boolean } & HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cx(styles.container, wide && styles.wide, className)} {...rest}>
      {children}
    </div>
  );
}

export function Rule({ dim = false }: { dim?: boolean }) {
  return <hr className={cx(styles.rule, dim && styles.ruleDim)} />;
}

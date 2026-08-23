import type { ReactNode } from "react";

import styles from "./Showcase.module.css";

/**
 * landing-page chrome. backgrounds come from the streak images in
 * /assets/brand and fall back to css gradients in the same palettes when a
 * file is missing. text over chrome is always white on a dark scrim (>= 7:1)
 */

export type Streak = 1 | 2 | 3 | 4;

/** full-bleed band with an image backdrop and white text */
export function ChromeBand({ streak = 2, children, className }: { streak?: Streak; children: ReactNode; className?: string }) {
  return (
    <section className={[styles.band, styles[`streak${streak}`], className].filter(Boolean).join(" ")}>
      <div className={styles.scrim} aria-hidden="true" />
      <div className={styles.bandInner}>{children}</div>
    </section>
  );
}

/** thin image strip on a paper card, with an optional white label */
export function ChromeStrip({ streak = 1, label }: { streak?: Streak; label?: ReactNode }) {
  return (
    <div className={[styles.strip, styles[`streak${streak}`]].join(" ")} aria-hidden={label ? undefined : true}>
      {label ? <span className={styles.stripLabel}>{label}</span> : null}
    </div>
  );
}

/** product screenshot in a paper frame with an ink rule */
export function Screenshot({ src, alt, caption, priority = false }: { src: string; alt: string; caption?: string; priority?: boolean }) {
  return (
    <figure className={styles.shot}>
      <img src={src} alt={alt} loading={priority ? "eager" : "lazy"} decoding="async" />
      {caption ? <figcaption>{caption}</figcaption> : null}
    </figure>
  );
}

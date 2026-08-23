import type { ReactNode } from "react";

import styles from "./Table.module.css";

export function Table({ columns, children, caption }: { columns: Array<{ key: string; label: ReactNode; width?: string }>; children: ReactNode; caption?: string }) {
  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        {caption ? <caption className={styles.caption}>{caption}</caption> : null}
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col" style={c.width ? { width: c.width } : undefined}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

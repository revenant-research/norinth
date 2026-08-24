import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";

import styles from "./Field.module.css";

type Common = { label: ReactNode; hint?: ReactNode; error?: ReactNode; className?: string };

function Wrap({ id, label, hint, error, className, children }: Common & { id: string; children: ReactNode }) {
  return (
    <div className={[styles.field, className].filter(Boolean).join(" ")}>
      <label className={styles.label} htmlFor={id}>
        {label}
      </label>
      {children}
      {hint ? (
        <span className={styles.hint} id={`${id}-hint`}>
          {hint}
        </span>
      ) : null}
      {error ? (
        <span className={styles.error} id={`${id}-error`} role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}

function describedBy(id: string, hint?: ReactNode, error?: ReactNode): string | undefined {
  const ids = [hint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean);
  return ids.length ? ids.join(" ") : undefined;
}

/** labelled text input with hint/error wiring (ids, aria-describedby, aria-invalid) */
export function TextField({ label, hint, error, className, id: givenId, ...rest }: Common & InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId();
  const id = givenId ?? auto;
  return (
    <Wrap id={id} label={label} hint={hint} error={error} className={className}>
      <input id={id} className={styles.control} aria-describedby={describedBy(id, hint, error)} aria-invalid={error ? true : undefined} {...rest} />
    </Wrap>
  );
}

export function TextArea({ label, hint, error, className, id: givenId, ...rest }: Common & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const auto = useId();
  const id = givenId ?? auto;
  return (
    <Wrap id={id} label={label} hint={hint} error={error} className={className}>
      <textarea id={id} className={styles.control} aria-describedby={describedBy(id, hint, error)} aria-invalid={error ? true : undefined} {...rest} />
    </Wrap>
  );
}

export function SelectField({
  label,
  hint,
  error,
  className,
  id: givenId,
  options,
  ...rest
}: Common & { options: Array<{ value: string; label: string }> } & SelectHTMLAttributes<HTMLSelectElement>) {
  const auto = useId();
  const id = givenId ?? auto;
  return (
    <Wrap id={id} label={label} hint={hint} error={error} className={className}>
      <select id={id} className={styles.control} aria-describedby={describedBy(id, hint, error)} {...rest}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </Wrap>
  );
}

export function Checkbox({ label, className, id: givenId, ...rest }: { label: ReactNode; className?: string } & InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId();
  const id = givenId ?? auto;
  return (
    <label className={[styles.check, className].filter(Boolean).join(" ")} htmlFor={id}>
      <input id={id} type="checkbox" className={styles.checkbox} {...rest} />
      <span>{label}</span>
    </label>
  );
}

/** lays fields out in a responsive grid; `inline` keeps them on one row */
export function FormGrid({ children, inline = false, className }: { children: ReactNode; inline?: boolean; className?: string }) {
  return <div className={[styles.grid, inline && styles.inline, className].filter(Boolean).join(" ")}>{children}</div>;
}

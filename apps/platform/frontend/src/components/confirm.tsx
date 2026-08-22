import { useEffect, useState } from "react";

/**
 * Promise-based confirmation dialog.
 *
 * Consequential actions (suspending a tenant, deactivating a user, revoking a
 * role, resetting a password) should never fire on a single unguarded click.
 * A module-level bus lets any handler `await confirm({...})` and branch on the
 * result without threading modal state through the component tree. A single
 * ConfirmHost, mounted once at the app root, renders the active request.
 */
export type ConfirmTone = "default" | "danger";

export type ConfirmRequest = {
  title: string;
  body: string;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: ConfirmTone;
};

type PendingRequest = ConfirmRequest & { id: number; resolve: (ok: boolean) => void };
type Listener = (pending: PendingRequest | null) => void;

let pending: PendingRequest | null = null;
const listeners = new Set<Listener>();
let nextId = 1;

function emit(): void {
  listeners.forEach((listener) => listener(pending));
}

function settle(ok: boolean): void {
  if (!pending) return;
  const { resolve } = pending;
  pending = null;
  emit();
  resolve(ok);
}

/** Open a confirmation dialog and resolve true only if the user confirms. */
export function confirm(request: ConfirmRequest): Promise<boolean> {
  return new Promise((resolve) => {
    pending = { ...request, id: nextId++, resolve };
    emit();
  });
}

export function ConfirmHost() {
  const [request, setRequest] = useState<PendingRequest | null>(null);

  useEffect(() => {
    const listener: Listener = (next) => setRequest(next);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  useEffect(() => {
    if (!request) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") settle(false);
      if (event.key === "Enter") settle(true);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [request]);

  if (!request) return null;
  const danger = request.tone === "danger";
  return (
    <div className="confirm-overlay" role="presentation" onMouseDown={() => settle(false)}>
      <div
        className="confirm-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-body"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <h2 id="confirm-title" className="confirm-title">
          {request.title}
        </h2>
        <p id="confirm-body" className="confirm-body">
          {request.body}
        </p>
        <div className="confirm-actions">
          <button className="secondary" onClick={() => settle(false)}>
            {request.cancelLabel || "Cancel"}
          </button>
          <button className={danger ? "danger" : ""} onClick={() => settle(true)} autoFocus>
            {request.confirmLabel || "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useRef, useState } from "react";

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
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const confirmRef = useRef<HTMLButtonElement | null>(null);
  const invokerRef = useRef<Element | null>(null);

  useEffect(() => {
    const listener: Listener = (next) => setRequest(next);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  useEffect(() => {
    if (!request) return;
    // Remember what had focus so we can restore it when the dialog closes, and
    // move focus into the dialog (onto the confirm button) on open.
    invokerRef.current = document.activeElement;
    confirmRef.current?.focus();

    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        settle(false);
        return;
      }
      // Do NOT globally bind Enter to confirm: a keyboard user on the Cancel
      // button pressing Enter would otherwise trigger the destructive action.
      // Enter/Space on the focused button is handled natively. Trap Tab so focus
      // cannot leave the modal.
      if (event.key === "Tab") {
        const focusables = [cancelRef.current, confirmRef.current].filter(Boolean) as HTMLButtonElement[];
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;
        if (event.shiftKey && active === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && active === last) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      // Restore focus to the element that opened the dialog.
      if (invokerRef.current instanceof HTMLElement) invokerRef.current.focus();
    };
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
          <button ref={cancelRef} className="secondary" onClick={() => settle(false)}>
            {request.cancelLabel || "Cancel"}
          </button>
          <button ref={confirmRef} className={danger ? "danger" : ""} onClick={() => settle(true)} autoFocus>
            {request.confirmLabel || "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}

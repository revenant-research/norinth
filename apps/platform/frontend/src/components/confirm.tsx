import { useEffect, useRef, useState } from "react";

// promise-based confirmation dialog for destructive actions. a module-level bus
// lets any handler `await confirm({...})` and branch on the result without
// threading modal state through the tree. one ConfirmHost at the app root
// renders the active request
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

/** open a dialog and resolve true only if the user confirms */
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
    // remember what had focus to restore on close, then focus the confirm button
    invokerRef.current = document.activeElement;
    confirmRef.current?.focus();

    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        settle(false);
        return;
      }
      // don't globally bind enter to confirm: a keyboard user on cancel pressing
      // enter would trigger the destructive action. enter/space on the focused
      // button is handled natively. trap tab so focus can't leave the modal
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
      // restore focus to the element that opened the dialog
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

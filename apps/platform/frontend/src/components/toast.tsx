import { useEffect, useState } from "react";

/**
 * Lightweight toast notifications.
 *
 * A module-level pub/sub bus lets any component raise a transient notification
 * without threading callbacks through the tree. A single ToastHost, mounted once
 * at the app root, subscribes and renders the stack. Toasts auto-dismiss; errors
 * linger a little longer so they are not missed.
 */
export type ToastTone = "success" | "error" | "info";

type Toast = { id: number; tone: ToastTone; message: string };
type Listener = (toasts: Toast[]) => void;

let activeToasts: Toast[] = [];
const listeners = new Set<Listener>();
let nextId = 1;

function emit(): void {
  const snapshot = [...activeToasts];
  listeners.forEach((listener) => listener(snapshot));
}

function dismiss(id: number): void {
  activeToasts = activeToasts.filter((item) => item.id !== id);
  emit();
}

function notify(message: string, tone: ToastTone): void {
  const id = nextId++;
  activeToasts = [...activeToasts, { id, tone, message }];
  emit();
  window.setTimeout(() => dismiss(id), tone === "error" ? 6000 : 4000);
}

export const toast = {
  success: (message: string) => notify(message, "success"),
  error: (message: string) => notify(message, "error"),
  info: (message: string) => notify(message, "info"),
};

export function ToastHost() {
  const [items, setItems] = useState<Toast[]>([]);

  useEffect(() => {
    const listener: Listener = (next) => setItems(next);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  if (!items.length) return null;
  return (
    <div className="toast-host" role="status" aria-live="polite">
      {items.map((item) => (
        <div className={`toast toast-${item.tone}`} key={item.id}>
          <span className="toast-message">{item.message}</span>
          <button className="toast-close" aria-label="Dismiss notification" onClick={() => dismiss(item.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

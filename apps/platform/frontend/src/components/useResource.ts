import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Load a resource and expose a stable `reload`.
 *
 * Always calls the LATEST loader: a previous version captured the first loader
 * closure permanently (useCallback with []), so filter changes never took
 * effect. Guards against setState-after-unmount and out-of-order responses.
 */
export function useResource<T>(loader: () => Promise<T>): { value: T | null; error: string; reload: () => void } {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState("");
  // Always call the LATEST loader. Previously `reload` captured the first
  // loader closure permanently (useCallback with []), so filter changes never
  // took effect — "Apply filters" was a silent no-op (audit frontend bug).
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  // Guards against setState-after-unmount and out-of-order responses.
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);
  const reload = useCallback(() => {
    const requestId = ++requestIdRef.current;
    loaderRef
      .current()
      .then((next) => {
        if (!mountedRef.current || requestId !== requestIdRef.current) return;
        setValue(next);
        setError("");
      })
      .catch((caught) => {
        if (!mountedRef.current || requestId !== requestIdRef.current) return;
        setError(caught instanceof Error ? caught.message : "Unable to load.");
      });
  }, []);
  useEffect(() => {
    reload();
  }, [reload]);
  return { value, error, reload };
}

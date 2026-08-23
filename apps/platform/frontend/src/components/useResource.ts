import { useCallback, useEffect, useRef, useState } from "react";

// load a resource and expose a stable `reload`. always calls the latest loader
// so filter changes take effect. guards against setState-after-unmount and
// out-of-order responses
export function useResource<T>(loader: () => Promise<T>): { value: T | null; error: string; reload: () => void } {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState("");
  // keep a ref to the latest loader so `reload` always calls the current one
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  // guards against setState-after-unmount and out-of-order responses
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

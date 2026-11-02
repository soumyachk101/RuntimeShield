// Small data-fetching hook used by every screen: loading / error / data
// with a retry handle. No suspense, no caching layer — screens own their
// query state, and the console must surface real loading/empty/error
// states (spec §18: "UI has real empty/loading/error/permission states").

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api";

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: ApiError | null;
  retry: () => void;
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fnRef
      .current()
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof ApiError ? e : new ApiError(0, String(e), null));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, ...deps]);

  const retry = useCallback(() => setTick((t) => t + 1), []);
  return { data, loading, error, retry };
}

// Human-facing label for an ApiError, including the 401/403 permission case
// (operator identity required) so the error state is specific. Accepts a
// plain Error too (the console narrows unknown → Error before calling).
export function apiErrorMessage(e: Error): string {
  const status = (e as ApiError).status;
  if (status === 401) return "401 — operator identity required. Check the operator id in the top bar (X-RS-Operator).";
  if (status === 403) return "403 — the operator is not permitted for this organisation.";
  if (status >= 400 && status !== 0) return `${status} — ${e.message}`;
  return e.message;
}

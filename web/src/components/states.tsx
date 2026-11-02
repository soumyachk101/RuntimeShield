// Shared status states: every screen must show honest loading / empty /
// error (and the 401 permission-denied case) — spec §18.
import type { ReactNode } from "react";
import { apiErrorMessage } from "../lib/useAsync";

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="rs-state" role="status">
      <div className="rs-spinner" aria-hidden="true" />
      <h3>{label}</h3>
      <p>Waiting for the control plane.</p>
    </div>
  );
}

export function EmptyState({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="rs-state">
      <h3>{title}</h3>
      {hint ? <p>{hint}</p> : null}
      {children}
    </div>
  );
}

export function ErrorState({
  error,
  title = "Could not reach the control plane",
  onRetry,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
}) {
  const msg = error instanceof Error ? apiErrorMessage(error) : String(error);
  const isPermission = /401|403/.test(msg);
  return (
    <div className="rs-state" role="alert">
      <span className={`rs-badge ${isPermission ? "rs-badge--warning" : "rs-badge--danger"}`}>
        <span className="dot" aria-hidden="true" />
        {isPermission ? "permission" : "error"}
      </span>
      <h3>{title}</h3>
      <p className="rs-mono">{msg}</p>
      {isPermission ? (
        <p>
          The operator identity sent as <code>X-RS-Operator</code> was rejected. Set a valid operator id in the
          top bar and retry.
        </p>
      ) : (
        <p>
          The console is same-origin: in dev it proxies <code>/v1</code> to the control plane (default{" "}
          <code>http://localhost:8080</code>, overridable via <code>RUNSHIELD_CONTROL_PLANE</code> in
          <code> vite.config.ts</code>). Check the control plane is running and the backend is healthy.
        </p>
      )}
      {onRetry ? (
        <button type="button" className="rs-btn rs-btn--sm" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

// The three states in one: render exactly one, honestly. `isEmpty` lets a
// caller report an empty collection ([]) distinct from a load error.
export function AsyncState<T>({
  data,
  loading,
  error,
  isEmpty,
  empty,
  children,
  onRetry,
  loadingLabel,
}: {
  data: T | null;
  loading: boolean;
  error: unknown;
  isEmpty: boolean;
  empty: { title: string; hint?: string; children?: ReactNode };
  children: (data: T) => ReactNode;
  onRetry?: () => void;
  loadingLabel?: string;
}) {
  if (loading) return <LoadingState label={loadingLabel} />;
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (isEmpty || data == null)
    return (
      <EmptyState title={empty.title} hint={empty.hint}>
        {empty.children}
      </EmptyState>
    );
  return children(data);
}

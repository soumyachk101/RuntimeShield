import { Component, useCallback, useEffect, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { loadOperator, loadTheme, saveOperator, saveTheme } from "./lib/session";
import { api, getOperatorId } from "./lib/api";
import { TeamAdmin } from "./components/TeamAdmin";
import { PolicyEditor } from "./components/PolicyEditor";
import { AuditTimeline } from "./components/AuditTimeline";
import { ApprovalsWorkspace } from "./components/ApprovalsWorkspace";

// --- lightweight hash router ------------------------------------------------
type Route = "team" | "policies" | "audit" | "approvals";

const ROUTES: Array<{ id: Route; label: string; aria: string }> = [
  { id: "team", label: "Team", aria: "Team admin" },
  { id: "policies", label: "Policies", aria: "Policy editor" },
  { id: "audit", label: "Audit", aria: "Audit timeline" },
  { id: "approvals", label: "Approvals", aria: "Approval workspace" },
];

function routeFromHash(): Route {
  const h = window.location.hash.replace(/^#\/?/, "");
  return (ROUTES.find((r) => r.id === h)?.id ?? "team") as Route;
}

function navigate(route: Route) {
  window.location.hash = `/${route}`;
}

function useHashRoute(): [Route, (r: Route) => void] {
  const [route, setRoute] = useState<Route>(routeFromHash);
  useEffect(() => {
    const onHash = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const go = useCallback((r: Route) => navigate(r), []);
  return [route, go];
}

// --- error boundary ----------------------------------------------------------
class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("RuntimeShield console crashed", error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="rs-main">
          <div className="rs-state" role="alert">
            <span className="rs-badge rs-badge--danger">
              <span className="dot" aria-hidden="true" /> crash
            </span>
            <h3>The console hit an unexpected error</h3>
            <p className="rs-mono">{String(this.state.error)}</p>
            <button
              type="button"
              className="rs-btn"
              onClick={() => {
                this.setState({ error: null });
              }}
            >
              Reload screen
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// --- health strip ------------------------------------------------------------
function useHealth() {
  const [health, setHealth] = useState<{ status: string; backend: string; nats: boolean } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .health()
      .then((h) => {
        if (!cancelled) setHealth(h);
      })
      .catch((e: unknown) => {
        if (!cancelled) setErr(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return { health, err };
}

// App entry: seed the module-level operator id + theme from localStorage,
// then render. loadOperator() pushes the stored id into the api client so
// the very first request already carries a valid X-RS-Operator.
function bootstrap() {
  loadOperator();
  loadTheme();
}
bootstrap();

// --- top bar -----------------------------------------------------------------
function TopBar({ route, onNav }: { route: Route; onNav: (r: Route) => void }) {
  const { health, err: healthErr } = useHealth();
  const [operator, setOperator] = useState(getOperatorId());
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => setTheme(loadTheme()), []);
  const themeToggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    saveTheme(next);
    setTheme(next);
  };

  const healthBadge = healthErr ? "error" : health ? health.status : "loading";

  return (
    <header className="rs-topbar">
      <div className="rs-brand">
        <span className="rs-brand-mark" aria-hidden="true">
          RS
        </span>
        <div>
          <div className="rs-brand-name">RuntimeShield</div>
          <div className="rs-brand-sub">control console</div>
        </div>
      </div>

      <nav className="rs-nav" aria-label="Console screens">
        {ROUTES.map((r) => (
          <button
            key={r.id}
            type="button"
            aria-label={r.aria}
            aria-current={route === r.id ? "page" : undefined}
            onClick={() => onNav(r.id)}
          >
            {r.label}
          </button>
        ))}
      </nav>

      <div className="rs-topbar-spacer" />

      <div className="rs-topbar-ctx">
        <div className="rs-field">
          <label htmlFor="op-id" style={{ position: "absolute", left: -9999 }}>
            Operator id
          </label>
          <input
            id="op-id"
            className="rs-input rs-mono"
            style={{ width: 130, fontSize: "0.75rem" }}
            aria-label="Operator id (sent as X-RS-Operator)"
            value={operator}
            onChange={(e) => setOperator(e.target.value)}
            onBlur={() => saveOperator(operator)}
            placeholder="operator id"
          />
        </div>
        <button
          type="button"
          className="rs-btn rs-btn--ghost rs-btn--sm"
          onClick={themeToggle}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? "light" : "dark"}
        </button>
        <span
          className={`rs-badge ${
            healthBadge === "ok"
              ? "rs-badge--success"
              : healthBadge === "error"
                ? "rs-badge--danger"
                : healthBadge === "degraded"
                  ? "rs-badge--warning"
                  : "rs-badge--neutral"
          }`}
          title={healthErr ? `control plane unreachable: ${healthErr}` : `backend ${health?.backend ?? "…"}`}
        >
          <span className="dot" aria-hidden="true" />
          {healthBadge === "ok" ? "api ok" : healthBadge === "error" ? "api down" : healthBadge}
        </span>
      </div>
    </header>
  );
}

// --- app ---------------------------------------------------------------------
export function App() {
  const [route, go] = useHashRoute();

  const screen =
    route === "team" ? (
      <TeamAdmin />
    ) : route === "policies" ? (
      <PolicyEditor />
    ) : route === "audit" ? (
      <AuditTimeline />
    ) : (
      <ApprovalsWorkspace />
    );

  return (
    <div className="rs-app">
      <TopBar route={route} onNav={go} />
      <ErrorBoundary>
        <main className="rs-main">{screen}</main>
      </ErrorBoundary>
      <footer style={{ width: "100%", maxWidth: "var(--rs-frame-max)", margin: "0 auto", padding: "0 24px 40px" }}>
        <p style={{ fontSize: "0.7rem", color: "var(--rs-text-3)", margin: 0 }}>
          RuntimeShield control console · same-origin <code>/v1</code> API · enforcement lives in the
          Rust agent, not here.
        </p>
      </footer>
    </div>
  );
}

// Audit timeline: the decision events ingested into the control plane, with
// filters (device, policy version, decision kind) and rule IDs + safe
// remediation surfaced on denials. Reads GET /v1/decisions (store.DecisionRow,
// a decision joined to its requesting device).
import { useState } from "react";
import { api, DECISION_KINDS } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { remediationFor, isActionable } from "../lib/remediation";
import type { DecisionRow, DecisionFilter } from "../lib/types";
import { AsyncState } from "./states";
import { DecisionBadge } from "./badge";

export function AuditTimeline() {
  const [filters, setFilters] = useState<DecisionFilter>({});
  const [active, setActive] = useState<DecisionRow | null>(null);

  // Re-query only when the filters actually change.
  const filtersKey = JSON.stringify(filters);
  const data = useAsync(() => api.decisions({ limit: 200, ...filters }), [filtersKey]);

  const rows = data.data?.items ?? [];
  const isEmpty = data.data != null && rows.length === 0;

  const set = (patch: Partial<DecisionFilter>) => setFilters((f) => ({ ...f, ...patch }));
  const clear = () => {
    setFilters({});
    setActive(null);
  };

  const ruleIds = (row: DecisionRow): string[] => {
    try {
      const parsed = JSON.parse(row.rule_ids);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return row.rule_ids ? [row.rule_ids] : [];
    }
  };

  return (
    <div className="rs-screen">
      <div className="rs-screen-head">
        <div className="rs-title">
          <h1>Audit timeline</h1>
          <p>
            Decision events ingested from devices, newest first. Denials carry the matched rule IDs
            and the safe remediation the engine produced. Read via GET /v1/decisions.
          </p>
        </div>
      </div>

      {/* filters */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Filters</span>
        </div>
        <div className="rs-panel-body">
          <div className="rs-row">
            <div className="rs-field">
              <label htmlFor="f-device">Device</label>
              <input
                id="f-device"
                className="rs-input rs-mono"
                placeholder="device_id"
                value={filters.device_id ?? ""}
                onChange={(e) => set({ device_id: e.target.value || undefined })}
              />
            </div>
            <div className="rs-field">
              <label htmlFor="f-policy">Policy version</label>
              <input
                id="f-policy"
                className="rs-input rs-mono"
                placeholder="e.g. 0.1.0"
                value={filters.policy_version ?? ""}
                onChange={(e) => set({ policy_version: e.target.value || undefined })}
              />
            </div>
            <div className="rs-field">
              <label htmlFor="f-decision">Decision</label>
              <select
                id="f-decision"
                className="rs-select"
                value={filters.decision ?? ""}
                onChange={(e) => set({ decision: (e.target.value || undefined) as DecisionFilter["decision"] })}
              >
                <option value="">any</option>
                {DECISION_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
            </div>
            <button type="button" className="rs-btn rs-btn--ghost" onClick={clear}>
              Clear
            </button>
          </div>
        </div>
      </section>

      {/* timeline */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">
            Decisions · {rows.length} shown
          </span>
          <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
            {filters.device_id ? `device=${filters.device_id} · ` : ""}
            {filters.policy_version ? `policy=${filters.policy_version} · ` : ""}
            {filters.decision ? `decision=${filters.decision}` : "all"}
          </span>
        </div>
        <AsyncState
          data={rows}
          loading={data.loading}
          error={data.error}
          isEmpty={isEmpty}
          loadingLabel="Loading decisions…"
          onRetry={data.retry}
          empty={{
            title: "No decisions match these filters",
            hint: "The control plane has no decision rows yet, or the filter excludes them all. Clear the filters or seed events via POST /v1/events/batch.",
          }}
        >
          {(items) => (
            <ul className="rs-timeline" aria-label="decision timeline, newest first">
              {items.map((row) => {
                const ids = ruleIds(row);
                const actionable = isActionable(row.decision);
                const open = active?.id === row.id;
                return (
                  <li key={row.id}>
                    <span
                      className="rs-tl-node"
                      style={{
                        color:
                          row.decision === "allow"
                            ? "var(--rs-success)"
                            : row.decision === "deny"
                              ? "var(--rs-danger)"
                              : row.decision === "require_approval"
                                ? "var(--rs-warning)"
                                : "var(--rs-info)",
                      }}
                      aria-hidden="true"
                    >
                      {row.decision === "allow" ? "✓" : row.decision === "deny" ? "✕" : row.decision === "require_approval" ? "?" : "i"}
                    </span>
                    <div className="rs-tl-body">
                      <div className="rs-tl-meta" style={{ marginBottom: 4 }}>
                        <DecisionBadge value={row.decision} />
                        <span className="rs-mono">{new Date(row.decided_at).toLocaleString()}</span>
                        <span className="rs-mono">policy {row.policy_version || "—"}</span>
                        <span className="rs-mono">device {row.device_id || "—"}</span>
                        <span className="rs-mono">req {row.request_id}</span>
                      </div>
                      {ids.length > 0 ? (
                        <div className="rs-ruleids" style={{ marginBottom: open ? 8 : 4 }}>
                          {ids.map((id) => (
                            <code key={id}>{id}</code>
                          ))}
                        </div>
                      ) : null}
                      {actionable ? (
                        <div
                          className="rs-callout"
                          style={{
                            borderColor: row.decision === "deny" ? "var(--rs-danger)" : "var(--rs-warning)",
                            background: row.decision === "deny" ? "var(--rs-danger-bg)" : "var(--rs-warning-bg)",
                            cursor: "pointer",
                          }}
                          onClick={() => setActive(open ? null : row)}
                          aria-expanded={open}
                        >
                          <strong>{row.decision === "deny" ? "Safe next step" : "Approval required"}</strong>{" "}
                          <span style={{ opacity: 0.85 }}>({ids[0] ?? "section rule"})</span>
                          {open ? <div style={{ marginTop: 6 }}>{remediationFor(ids)}</div> : null}
                        </div>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </AsyncState>
      </section>
    </div>
  );
}

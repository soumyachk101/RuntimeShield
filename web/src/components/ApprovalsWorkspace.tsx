// Approval workspace: pending REQUIRE_APPROVAL requests, approve/deny with
// the requested scope + expiry, and decision history.
//  - pending list:        GET  /v1/approvals?status=pending
//  - decide:              POST /v1/approvals/{id}/decision  {decision: allow|deny}
//  - history:             GET  /v1/approvals?status=approved|denied (decision history)
//  - manual request:      POST /v1/approvals {request_id, scope, reason?}
//  - decision trace:      GET  /v1/decisions?decision=require_approval (the filtered decisions endpoint)
import { useState } from "react";
import { api, ApiError } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import type { Approval, ApprovalDecisionBody } from "../lib/types";
import { AsyncState } from "./states";
import { DecisionBadge, StatusBadge, Toast } from "./badge";

type HistoryStatus = "" | "approved" | "denied";

export function ApprovalsWorkspace() {
  const pending = useAsync(() => api.approvals("pending"), []);
  const [historyStatus, setHistoryStatus] = useState<HistoryStatus>("");
  const history = useAsync(() => api.approvals(historyStatus), [historyStatus]);
  const reqDecisions = useAsync(() => api.decisions({ decision: "require_approval", limit: 50 }), []);

  const [busy, setBusy] = useState<string | null>(null); // approval id mid-decision
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  const decide = async (approval: Approval, decision: "allow" | "deny") => {
    setBusy(approval.id);
    setToast(null);
    try {
      const body: ApprovalDecisionBody = { decision };
      const res = await api.decideApproval(approval.id, body);
      setToast({ tone: "ok", text: `Approval ${approval.id} ${res.decision === "allow" ? "granted" : "denied"} by ${res.approver_id}.` });
      pending.retry();
      history.retry();
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status} — ${e.message}` : String(e);
      setToast({ tone: "err", text: `Decision not recorded: ${msg}` });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="rs-screen">
      <div className="rs-screen-head">
        <div className="rs-title">
          <h1>Approval workspace</h1>
          <p>
            Approve or deny pending REQUIRE_APPROVAL requests with their requested scope and
            expiry, and review the decision history. A deny cannot widen a policy; approvals are
            scoped and expiring (spec §4.1 FR-06).
          </p>
        </div>
      </div>

      {toast ? <Toast tone={toast.tone}>{toast.text}</Toast> : null}

      {/* pending decisions */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Pending approvals</span>
          <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
            GET /v1/approvals?status=pending · {(pending.data?.items.length ?? 0)} waiting
          </span>
        </div>
        <AsyncState
          data={pending.data?.items ?? []}
          loading={pending.loading}
          error={pending.error}
          isEmpty={(pending.data?.items.length ?? 0) === 0}
          loadingLabel="Loading pending approvals…"
          onRetry={pending.retry}
          empty={{
            title: "Nothing pending",
            hint: "No REQUIRE_APPROVAL requests are awaiting a decision. Decided requests move to the history below.",
          }}
        >
          {(rows: Approval[]) => (
            <div className="rs-table-wrap">
              <table className="rs-table">
                <thead>
                  <tr>
                    <th>Approval</th>
                    <th>Request</th>
                    <th>Requested scope</th>
                    <th>Expires</th>
                    <th>Approver</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <div className="rs-strong rs-mono">{a.id}</div>
                        <div style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
                          created {new Date(a.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="rs-mono">{a.request_id}</td>
                      <td>
                        <code className="rs-mono">{a.scope}</code>
                      </td>
                      <td className="rs-mono">{relTime(a.expires_at)}</td>
                      <td className="rs-mono">{a.approver_id}</td>
                      <td>
                        <div style={{ display: "flex", gap: 6 }}>
                          <button
                            type="button"
                            className="rs-btn rs-btn--sm rs-btn--primary"
                            disabled={busy === a.id}
                            onClick={() => decide(a, "allow")}
                          >
                            Approve
                          </button>
                          <button
                            type="button"
                            className="rs-btn rs-btn--sm rs-btn--danger"
                            disabled={busy === a.id}
                            onClick={() => decide(a, "deny")}
                          >
                            Deny
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncState>
      </section>

      {/* decision history */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Decision history</span>
          <div className="rs-row" style={{ gap: 6 }}>
            {(["", "approved", "denied"] as const).map((s) => (
              <button
                key={s || "all"}
                type="button"
                className={`rs-btn rs-btn--sm ${historyStatus === s ? "rs-btn--primary" : "rs-btn--ghost"}`}
                onClick={() => setHistoryStatus(s as HistoryStatus)}
              >
                {s === "" ? "all" : s}
              </button>
            ))}
          </div>
        </div>
        <AsyncState
          data={history.data?.items ?? []}
          loading={history.loading}
          error={history.error}
          isEmpty={(history.data?.items.length ?? 0) === 0}
          loadingLabel="Loading decision history…"
          onRetry={history.retry}
          empty={{
            title: "No decisions recorded yet",
            hint: "Approve or deny a pending request above; decided approvals land here.",
          }}
        >
          {(rows: Approval[]) => (
            <div className="rs-table-wrap">
              <table className="rs-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Approval</th>
                    <th>Request</th>
                    <th>Scope</th>
                    <th>Approver</th>
                    <th>Recorded</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <StatusBadge value={a.status} />
                      </td>
                      <td className="rs-mono">{a.id}</td>
                      <td className="rs-mono">{a.request_id}</td>
                      <td>
                        <code className="rs-mono">{a.scope}</code>
                      </td>
                      <td className="rs-mono">{a.approver_id}</td>
                      <td className="rs-mono">{relTime(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncState>
      </section>

      {/* request-approval trace from the filtered decisions endpoint */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Require-approval decisions (audit trace)</span>
          <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
            GET /v1/decisions?decision=require_approval
          </span>
        </div>
        <AsyncState
          data={reqDecisions.data?.items ?? []}
          loading={reqDecisions.loading}
          error={reqDecisions.error}
          isEmpty={(reqDecisions.data?.items.length ?? 0) === 0}
          loadingLabel="Loading approval-required decisions…"
          onRetry={reqDecisions.retry}
          empty={{
            title: "No require-approval decisions in the audit log",
            hint: "When a policy rule demands approval, the agent journals REQUIRE_APPROVAL and uploads it; it appears here on the next ingest.",
          }}
        >
          {(rows) => (
            <div className="rs-table-wrap">
              <table className="rs-table">
                <thead>
                  <tr>
                    <th>Decision</th>
                    <th>Request</th>
                    <th>Rules</th>
                    <th>Policy</th>
                    <th>Device</th>
                    <th>Decided</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <DecisionBadge value={d.decision} />
                      </td>
                      <td className="rs-mono">{d.request_id}</td>
                      <td className="rs-mono">{d.rule_ids || "—"}</td>
                      <td className="rs-mono">{d.policy_version || "—"}</td>
                      <td className="rs-mono">{d.device_id || "—"}</td>
                      <td className="rs-mono">{relTime(d.decided_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncState>
      </section>

      {/* manual approval request (FR-06 allow-for-workspace / once) */}
      <ManualRequest onToast={setToast} onCreated={() => { pending.retry(); history.retry(); }} />
    </div>
  );
}

function ManualRequest({
  onToast,
  onCreated,
}: {
  onToast: (t: { tone: "ok" | "err"; text: string } | null) => void;
  onCreated: () => void;
}) {
  const [requestId, setRequestId] = useState("");
  const [scope, setScope] = useState("exec:");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!requestId.trim() || !scope.trim()) {
      onToast({ tone: "err", text: "request_id and scope are both required." });
      return;
    }
    setBusy(true);
    onToast(null);
    try {
      const res = await api.createApproval({ request_id: requestId.trim(), scope: scope.trim(), reason: reason.trim() || undefined });
      onToast({ tone: "ok", text: `Pending approval ${res.id} created for ${res.request_id} (expires ${res.expires_at}).` });
      setRequestId("");
      setScope("exec:");
      setReason("");
      onCreated();
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status} — ${e.message}` : String(e);
      onToast({ tone: "err", text: `Could not create the approval request: ${msg}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rs-panel">
      <div className="rs-panel-head">
        <span className="rs-label">Record a pending approval request</span>
        <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
          POST /v1/approvals
        </span>
      </div>
      <div className="rs-panel-body">
        <div className="rs-row">
          <div className="rs-field rs-field--grow">
            <label htmlFor="m-req">Request id</label>
            <input id="m-req" className="rs-input rs-mono" value={requestId} onChange={(e) => setRequestId(e.target.value)} placeholder="demo-0002" />
          </div>
          <div className="rs-field rs-field--grow">
            <label htmlFor="m-scope">Requested scope</label>
            <input id="m-scope" className="rs-input rs-mono" value={scope} onChange={(e) => setScope(e.target.value)} placeholder="exec:curl action:-s" />
          </div>
          <div className="rs-field rs-field--grow">
            <label htmlFor="m-reason">Reason (optional)</label>
            <input id="m-reason" className="rs-input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="time-boxed exception" />
          </div>
          <button type="button" className="rs-btn" disabled={busy} onClick={submit}>
            {busy ? "Recording…" : "Record request"}
          </button>
        </div>
        <p style={{ margin: "10px 0 0", fontSize: "0.72rem", color: "var(--rs-text-3)" }}>
          Expiry is set by the control plane (1 h by default). Keep scopes narrow — a scope string
          like <code>exec:curl action:-s</code>, not a blanket grant.
        </p>
      </div>
    </section>
  );
}

// Compact relative time for table cells.
function relTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso || "—";
  const diff = d.getTime() - Date.now();
  const past = diff < 0;
  const abs = Math.abs(diff);
  const mins = Math.round(abs / 60000);
  if (mins < 1) return past ? "just now" : "now";
  if (mins < 60) return `${mins}m ${past ? "ago" : "from now"}`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h ${past ? "ago" : "from now"}`;
  return d.toLocaleDateString();
}

// Team admin: organisations/users, enrolled devices, and device token
// issuance. Every list is a real /v1 operator route (server.go). The
// organisation is a local scope (until team-admin provisioning lands, the
// reference org endpoint returns an empty set — see the empty state).
import { useState } from "react";
import { api, ApiError } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { loadOrganization, saveOrganization } from "../lib/session";
import type { Device, DeviceTokenResponse, User } from "../lib/types";
import { AsyncState, ErrorState, LoadingState } from "./states";
import { StatusBadge } from "./badge";

const DEFAULT_ORG = "acme";

export function TeamAdmin() {
  const [org, setOrg] = useState(() => loadOrganization(DEFAULT_ORG));
  const [tokenResult, setTokenResult] = useState<DeviceTokenResponse | null>(null);
  const [tokenErr, setTokenErr] = useState<string | null>(null);
  const [issuingFor, setIssuingFor] = useState<string | null>(null);

  const users = useAsync(() => api.users(org), [org]);
  const devices = useAsync(() => api.devices(org), [org]);
  const orgs = useAsync(() => api.orgs(), []);

  const pickOrg = (value: string) => {
    saveOrganization(value);
    setOrg(value);
    setTokenResult(null);
  };

  const issueToken = async (device: Device) => {
    setIssuingFor(device.id);
    setTokenErr(null);
    setTokenResult(null);
    try {
      const res = await api.deviceToken(device.id, org);
      setTokenResult(res);
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status} — ${e.message}` : String(e);
      setTokenErr(msg);
      if (e instanceof ApiError && e.status === 503) {
        // Token issuer not configured (dev without a sign key).
        setTokenErr(
          "503 — the control plane has no token issuer configured. Set RUNSHIELD_SIGN_KEY on the control plane and restart, then retry.",
        );
      }
    } finally {
      setIssuingFor(null);
    }
  };

  return (
    <div className="rs-screen">
      <div className="rs-screen-head">
        <div className="rs-title">
          <h1>Team admin</h1>
          <p>
            Organisations, users and enrolled devices for one organisation. Token issuance mints a
            short-lived device credential via <code>POST /v1/devices/&#123;id&#125;/token</code>.
          </p>
        </div>
      </div>

      {/* org scope */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Organisation scope</span>
        </div>
        <div className="rs-panel-body">
          <div className="rs-row">
            <div className="rs-field rs-field--grow">
              <label htmlFor="org-select">Organisation</label>
              {orgs.data && orgs.data.items.length > 0 ? (
                <select
                  id="org-select"
                  className="rs-select"
                  value={org}
                  onChange={(e) => pickOrg(e.target.value)}
                >
                  {orgs.data.items.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              ) : (
                <>
                  <input
                    id="org-input"
                    className="rs-input rs-mono"
                    value={org}
                    onChange={(e) => pickOrg(e.target.value)}
                    placeholder="org id, e.g. acme"
                  />
                  <p style={{ margin: 0, fontSize: "0.75rem", color: "var(--rs-text-3)" }}>
                    No organisations are provisioned yet (<code>GET /v1/organizations</code> returns
                    empty in this reference build). Enter an org id to scope the lists; user and device
                    rows appear as soon as they are seeded in the store.
                  </p>
                </>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* users */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Users · {org}</span>
          <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
            GET /v1/users?organization={org}
          </span>
        </div>
        <AsyncState
          data={users.data?.items ?? []}
          loading={users.loading}
          error={users.error}
          isEmpty={(users.data?.items.length ?? 0) === 0}
          loadingLabel="Loading users…"
          onRetry={users.retry}
          empty={{
            title: "No users for this organisation",
            hint: "Users are read from the store's users table; none are seeded for " + org + " yet.",
          }}
        >
          {(rows: User[]) => (
            <div className="rs-table-wrap">
              <table className="rs-table">
                <thead>
                  <tr>
                    <th>User id</th>
                    <th>Identity provider</th>
                    <th>Role</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((u) => (
                    <tr key={u.id}>
                      <td>
                        <span className="rs-strong rs-mono">{u.id}</span>
                      </td>
                      <td className="rs-mono">{u.identity_provider_id || "—"}</td>
                      <td>
                        <StatusBadge value={u.role} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncState>
      </section>

      {/* devices */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Devices · {org}</span>
          <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
            GET /v1/devices?organization={org}
          </span>
        </div>
        <AsyncState
          data={devices.data?.items ?? []}
          loading={devices.loading}
          error={devices.error}
          isEmpty={(devices.data?.items.length ?? 0) === 0}
          loadingLabel="Loading devices…"
          onRetry={devices.retry}
          empty={{
            title: "No enrolled devices for this organisation",
            hint: "Devices appear after POST /v1/devices/enrol with a device_id and public key.",
          }}
        >
          {(rows: Device[]) => (
            <div className="rs-table-wrap">
              <table className="rs-table">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Platform</th>
                    <th>Agent</th>
                    <th>Last seen</th>
                    <th>Token</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <div className="rs-strong rs-mono">{d.id}</div>
                        <code style={{ fontSize: "0.7rem", opacity: 0.6 }}>
                          key {d.public_key.slice(0, 12)}…
                        </code>
                      </td>
                      <td>{d.platform}</td>
                      <td className="rs-mono">{d.agent_version || "—"}</td>
                      <td className="rs-mono">{d.last_seen_at || "never"}</td>
                      <td>
                        <button
                          type="button"
                          className="rs-btn rs-btn--sm"
                          disabled={issuingFor === d.id}
                          onClick={() => issueToken(d)}
                        >
                          {issuingFor === d.id ? "Issuing…" : "Issue token"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncState>
      </section>

      {/* token lifecycle result */}
      {tokenResult || tokenErr ? (
        <section className="rs-panel">
          <div className="rs-panel-head">
            <span className="rs-label">Device token lifecycle</span>
          </div>
          <div className="rs-panel-body">
            {tokenErr ? (
              <div className="rs-callout">
                <strong>Token issuance failed.</strong> <div>{tokenErr}</div>
              </div>
            ) : tokenResult ? (
              <div className="rs-toast rs-toast--ok">
                <div>
                  <div style={{ marginBottom: 6 }}>
                    Issued a device credential for <code className="rs-mono">{tokenResult.device}</code>{" "}
                    (expires {tokenResult.expires}).
                  </div>
                  <pre className="rs-code" style={{ margin: 0, maxHeight: 120 }}>
                    {tokenResult.token}
                  </pre>
                </div>
              </div>
            ) : null}
          </div>
        </section>
      ) : null}

      {/* orgs (honest: empty in reference build) */}
      <section className="rs-panel">
        <div className="rs-panel-head">
          <span className="rs-label">Organisations</span>
        </div>
        {orgs.loading ? <LoadingState label="Loading organisations…" /> : null}
        {orgs.error ? <ErrorState error={orgs.error} onRetry={orgs.retry} /> : null}
        {orgs.data && !orgs.loading && !orgs.error ? (
          <AsyncState
            data={orgs.data.items}
            loading={false}
            error={null}
            isEmpty={orgs.data.items.length === 0}
            empty={{
              title: "No organisations provisioned",
              hint: "The reference org endpoint returns an empty set; provisioning lands with FR-08.",
            }}
          >
            {(rows) => (
              <div className="rs-table-wrap">
                <table className="rs-table">
                  <thead>
                    <tr>
                      <th>Org</th>
                      <th>Plan</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((o) => (
                      <tr key={o.id}>
                        <td>
                          <span className="rs-strong">{o.name}</span>{" "}
                          <code style={{ fontSize: "0.7rem" }}>{o.id}</code>
                        </td>
                        <td>{o.plan}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </AsyncState>
        ) : null}
      </section>
    </div>
  );
}

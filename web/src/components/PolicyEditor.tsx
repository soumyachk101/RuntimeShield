// Policy editor: versioned policy list, per-version JSON editor with
// client-side JSON-schema validation (schema fetched from
// GET /v1/policies/schema — the same source the server validates against),
// sign/publish (POST /v1/policies, POST /v1/policies/{id}/publish),
// rollback (POST /v1/policies/{id}/rollback), and a diff view between two
// versions. The three example profiles load as starting templates and are
// labelled sample everywhere they appear.
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { loadOrganization, saveOrganization } from "../lib/session";
import { SAMPLE_PROFILES, sampleByProfileName } from "../lib/templates";
import { validatePolicyDocument } from "../lib/schema";
import type { PolicyVersion } from "../lib/types";
import { AsyncState } from "./states";
import { StatusBadge, Toast } from "./badge";
import { DiffView } from "./DiffView";
import { Carousel } from "./carousel";

const DEFAULT_ORG = "acme";

interface ToastState {
  tone: "ok" | "err";
  text: string;
}

type Mode =
  | { kind: "view"; id: string }
  | { kind: "new" }
  | { kind: "diff"; fromId: string; toId: string };

// A stored policy document is trusted JSON, but a malformed row should show
// an error state, not crash the screen into the boundary.
function tryParseDocument(doc: string): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: JSON.parse(doc) };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

export function PolicyEditor() {
  const [org, setOrg] = useState(() => loadOrganization(DEFAULT_ORG));
  const [mode, setMode] = useState<Mode>({ kind: "new" });
  const [toast, setToast] = useState<ToastState | null>(null);

  const list = useAsync(() => api.policies(org), [org]);
  const schema = useAsync(async () => (await api.policySchema()) as unknown as Record<string, unknown>, []);

  const versions = useMemo(() => list.data?.items ?? [], [list.data]);
  const pickOrg = (v: string) => {
    saveOrganization(v);
    setOrg(v);
    setMode({ kind: "new" });
  };

  const chosen = (id: string | undefined) => versions.find((p) => p.id === id);

  return (
    <div className="rs-screen">
      <div className="rs-screen-head">
        <div className="rs-title">
          <h1>Policy editor</h1>
          <p>
            Versioned policies, schema-validated JSON editing, sign &amp; publish, rollback and
            version diff. Drafts are validated and signed server-side; sample templates are
            labelled sample and must be reviewed before publishing.
          </p>
        </div>
        <div className="rs-row">
          <div className="rs-field">
            <label htmlFor="pol-org">Organisation</label>
            <input
              id="pol-org"
              className="rs-input rs-mono"
              value={org}
              onChange={(e) => pickOrg(e.target.value)}
            />
          </div>
        </div>
      </div>

      {toast ? <Toast tone={toast.tone}>{toast.text}</Toast> : null}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(280px, 380px) 1fr",
          gap: 0,
          border: "1px solid var(--rs-border-subtle)",
          borderRadius: "var(--rs-radius-md)",
          overflow: "hidden",
          background: "var(--rs-surface-1)",
        }}
      >
        {/* --- version list ------------------------------------------------- */}
        <div style={{ borderRight: "1px solid var(--rs-border-subtle)", padding: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3>Policies · {org}</h3>
            <button
              type="button"
              className="rs-btn rs-btn--sm rs-btn--ghost"
              onClick={() => setMode({ kind: "new" })}
            >
              New draft
            </button>
          </div>
          <AsyncState
            data={versions}
            loading={list.loading}
            error={list.error}
            isEmpty={versions.length === 0}
            loadingLabel="Loading policy versions…"
            onRetry={list.retry}
            empty={{
              title: "No policy versions yet",
              hint: "Create the first signed draft from a sample template on the right; POST /v1/policies signs and stores it.",
            }}
          >
            {(rows) => (
              <ul className="rs-timeline" aria-label="policy versions, newest first">
                {rows.map((p) => (
                  <li key={p.id}>
                    <span
                      className={`rs-tl-node ${p.status === "published" ? "" : "rs-tl-node"}`}
                      aria-hidden="true"
                      style={p.status === "published" ? { color: "var(--rs-success)" } : undefined}
                    >
                      v{p.version}
                    </span>
                    <div className="rs-tl-body">
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <StatusBadge value={p.status} />
                        <span className="rs-mono" style={{ fontSize: "0.75rem" }}>
                          {new Date(p.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="rs-tl-meta">
                        <button
                          type="button"
                          className="rs-btn rs-btn--ghost rs-btn--sm"
                          style={{ padding: "2px 6px" }}
                          onClick={() => setMode({ kind: "view", id: p.id })}
                        >
                          view
                        </button>
                        <button
                          type="button"
                          className="rs-btn rs-btn--ghost rs-btn--sm"
                          style={{ padding: "2px 6px" }}
                          onClick={() => {
                            // Diff this version against its nearest older one
                            // (the list is newest-first, so the first row with
                            // a lower version). Falls back to "create a draft
                            // from this version" if it is already the oldest.
                            const older = rows.find((x) => x.version < p.version);
                            if (older) {
                              setMode({ kind: "diff", fromId: older.id, toId: p.id });
                            } else {
                              setToast({
                                tone: "err",
                                text: `v${p.version} is the oldest version; nothing older to diff against.`,
                              });
                            }
                          }}
                        >
                          {rows.find((x) => x.version < p.version)
                            ? "diff vs older"
                            : "oldest version"}
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </AsyncState>
        </div>

        {/* --- editor / viewer / diff -------------------------------------- */}
        <div style={{ padding: "16px" }}>
          {mode.kind === "diff" ? (
            <DiffPane fromId={mode.fromId} toId={mode.toId} />
          ) : mode.kind === "view" ? (
            <EditorPane
              key={mode.id}
              version={chosen(mode.id)}
              org={org}
              schema={schema.data}
              schemaError={schema.error}
              onToast={setToast}
              onPublished={() => {
                list.retry();
              }}
            />
          ) : (
            <NewDraftPane
              org={org}
              versions={versions}
              schema={schema.data}
              schemaError={schema.error}
              onCreated={(p) => {
                list.retry();
                setMode({ kind: "view", id: p.id });
              }}
              onToast={setToast}
            />
          )}
        </div>
      </div>

      {/* --- sample profile carousel (the one place a carousel genuinely helps) --- */}
      <section>
        <div className="rs-panel-head" style={{ padding: 0, marginBottom: 12 }}>
          <h3>Sample profiles (starting templates)</h3>
          <span className="rs-badge rs-badge--sample">sample — review before publish</span>
        </div>
        <SampleCarousel />
      </section>
    </div>
  );
}

// --- sample carousel -----------------------------------------------------------

function SampleCarousel() {
  // The carousel only browses the shipped example profiles; it never shows
  // data that isn't labelled sample.
  const items = useMemo(
    () =>
      SAMPLE_PROFILES.map((s) => ({
        key: s.name,
        heading: s.document.profile,
        subheading: s.description,
        content: (
          <pre className="rs-code" style={{ margin: 0 }}>
            {JSON.stringify(s.document, null, 2)}
          </pre>
        ),
      })),
    [],
  );
  return <Carousel items={items} ariaLabel="Sample policy profiles" />;
}

// --- version diff pane ---------------------------------------------------------

function DiffPane({ fromId, toId }: { fromId: string; toId: string }) {
  const [a, setA] = useState<PolicyVersion | null>(null);
  const [b, setB] = useState<PolicyVersion | null>(null);
  const [err, setErr] = useState<unknown>(null);

  useEffect(() => {
    let cancelled = false;
    setErr(null);
    setA(null);
    setB(null);
    Promise.all([api.policy(fromId), api.policy(toId)])
      .then(([ra, rb]) => {
        if (!cancelled) {
          setA(ra.policy);
          setB(rb.policy);
        }
      })
      .catch((e) => {
        if (!cancelled) setErr(e);
      });
    return () => {
      cancelled = true;
    };
  }, [fromId, toId]);

  if (err)
    return (
      <div className="rs-callout">
        <strong>Could not load the versions to diff.</strong>{" "}
        <div>{err instanceof ApiError ? `${err.status} — ${err.message}` : String(err)}</div>
      </div>
    );
  if (!a || !b)
    return (
      <div className="rs-state">
        <div className="rs-spinner" />
        <h3>Loading versions…</h3>
      </div>
    );
  // Left = older (fromId, newer in list order), right = the one diffed "vs".
  const older = a.version <= b.version ? a : b;
  const newer = a.version <= b.version ? b : a;
  return (
    <div>
      <div style={{ marginBottom: 12 }}>
        <h2 style={{ marginBottom: 4 }}>
          Diff · v{older.version} → v{newer.version}
        </h2>
        <p style={{ margin: 0, fontSize: "0.8125rem", color: "var(--rs-text-2)" }}>
          GET /v1/policies/{older.id} and /v1/policies/{newer.id}. Review before republishing the
          newer version.
        </p>
      </div>
      <DiffView before={older.document} after={newer.document} beforeLabel={`v${older.version} (${older.status})`} afterLabel={`v${newer.version} (${newer.status})`} />
    </div>
  );
}

// --- per-version editor ---------------------------------------------------------

function EditorPane({
  version,
  org,
  schema,
  schemaError,
  onToast,
  onPublished,
}: {
  version: PolicyVersion | undefined;
  org: string;
  schema: Record<string, unknown> | null;
  schemaError: unknown;
  onToast: (t: ToastState | null) => void;
  onPublished: () => void;
}) {
  const [doc, setDoc] = useState<string>(() => {
    if (!version) return "";
    const p = tryParseDocument(version.document);
    return p.ok ? JSON.stringify(p.value, null, 2) : version.document;
  });
  const [busy, setBusy] = useState<string | null>(null);

  const parsed = useMemo(() => {
    try {
      return { ok: true as const, value: JSON.parse(doc) as unknown };
    } catch (e) {
      return { ok: false as const, error: String(e) };
    }
  }, [doc]);

  const validation = useMemo(
    () => (parsed.ok ? validatePolicyDocument(schema, parsed.value) : { valid: false, errors: [{ path: "", message: `invalid JSON: ${parsed.error}` }] }),
    [parsed, schema],
  );

  if (!version)
    return (
      <div className="rs-callout">
        <strong>Version not found.</strong>
        <div>The selected policy row no longer exists in the list; pick another version.</div>
      </div>
    );

  const sign = async (action: "publish" | "rollback" | "save") => {
    setBusy(action);
    onToast(null);
    try {
      if (action === "save") {
        if (!parsed.ok || !validation.valid) throw new Error("document does not pass schema validation");
        const res = await api.createPolicy({ organization: org, document: parsed.value });
        onToast({ tone: "ok", text: `Draft v${res.version} created and signed (${res.id}).` });
        onPublished();
      } else {
        const res =
          action === "publish"
            ? await api.publishPolicy(version.id)
            : await api.rollbackPolicy(version.id);
        onToast({ tone: "ok", text: `Policy ${res.id} → ${res.status}.` });
        onPublished();
      }
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status} — ${e.message}` : String(e);
      onToast({ tone: "err", text: `${action === "save" ? "Sign & draft" : "Action"} failed: ${msg}` });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap", marginBottom: 12 }}>
        <div>
          <h2 style={{ marginBottom: 2 }}>Version {version.version}</h2>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <StatusBadge value={version.status} />
            <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
              id {version.id} · sig {version.signature ? `${version.signature.slice(0, 10)}…` : "—"}
            </span>
          </div>
        </div>
        <div className="rs-row">
          <button type="button" className="rs-btn rs-btn--sm" disabled={busy !== null} onClick={() => sign("save")}>
            {busy === "save" ? "Signing…" : "Sign new draft"}
          </button>
          <button
            type="button"
            className="rs-btn rs-btn--sm rs-btn--primary"
            disabled={busy !== null || version.status === "published"}
            onClick={() => sign("publish")}
          >
            {busy === "publish" ? "Publishing…" : "Publish"}
          </button>
          <button
            type="button"
            className="rs-btn rs-btn--sm rs-btn--danger"
            disabled={busy !== null || version.status === "rolled_back"}
            onClick={() => sign("rollback")}
          >
            {busy === "rollback" ? "Rolling back…" : "Roll back"}
          </button>
        </div>
      </div>

      {/* validation */}
      {schemaError ? (
        <div className="rs-toast" style={{ marginBottom: 10 }}>
          Schema unavailable ({schemaError instanceof ApiError ? schemaError.status : "error"}); using
          structural fallback checks.
        </div>
      ) : null}
      {parsed.ok ? (
        validation.valid ? (
          <div className="rs-toast rs-toast--ok" style={{ marginBottom: 10 }}>
            Valid against the policy schema.
          </div>
        ) : (
          <div className="rs-callout" style={{ marginBottom: 10 }}>
            <strong>Schema validation failed ({validation.errors.length}).</strong>
            <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
              {validation.errors.slice(0, 12).map((e, i) => (
                <li key={i} className="rs-mono" style={{ fontSize: "0.75rem" }}>
                  <code>{e.path}</code> {e.message}
                </li>
              ))}
            </ul>
          </div>
        )
      ) : (
        <div className="rs-callout" style={{ marginBottom: 10 }}>
          <strong>Not valid JSON.</strong>
          <div className="rs-mono" style={{ fontSize: "0.75rem" }}>
            {parsed.error}
          </div>
        </div>
      )}

      <textarea
        className="rs-textarea"
        style={{ minHeight: 280 }}
        aria-label="policy document JSON"
        value={doc}
        onChange={(e) => setDoc(e.target.value)}
        spellCheck={false}
      />
      <p style={{ fontSize: "0.7rem", color: "var(--rs-text-3)", margin: "8px 0 0" }}>
        Editing changes the document locally; “Sign new draft” creates a new signed version via
        POST /v1/policies. The existing version {version.id} is not mutated.
      </p>
    </div>
  );
}

// --- new draft pane -----------------------------------------------------------

function NewDraftPane({
  org,
  versions,
  schema,
  schemaError,
  onCreated,
  onToast,
}: {
  org: string;
  versions: PolicyVersion[];
  schema: Record<string, unknown> | null;
  schemaError: unknown;
  onCreated: (p: { id: string }) => void;
  onToast: (t: ToastState | null) => void;
}) {
  const [template, setTemplate] = useState<string>("repository-development");
  const sample = sampleByProfileName(template);
  const [doc, setDoc] = useState<string>(() =>
    sample ? JSON.stringify(sample.document, null, 2) : "{}",
  );

  const parsed = useMemo(() => {
    try {
      return { ok: true as const, value: JSON.parse(doc) as unknown };
    } catch (e) {
      return { ok: false as const, error: String(e) };
    }
  }, [doc]);
  const validation = useMemo(
    () => (parsed.ok ? validatePolicyDocument(schema, parsed.value) : { valid: false, errors: [{ path: "", message: `invalid JSON: ${parsed.error}` }] }),
    [parsed, schema],
  );

  const create = async () => {
    if (!parsed.ok || !validation.valid) {
      onToast({ tone: "err", text: "Draft blocked: the document does not pass validation." });
      return;
    }
    try {
      const res = await api.createPolicy({ organization: org, document: parsed.value });
      onToast({ tone: "ok", text: `Signed draft v${res.version} created (${res.id}). Publish to activate.` });
      onCreated(res);
    } catch (e) {
      const msg = e instanceof ApiError ? `${e.status} — ${e.message}` : String(e);
      onToast({ tone: "err", text: `Could not create the draft: ${msg}` });
    }
  };

  return (
    <div>
      <div style={{ marginBottom: 12 }}>
        <h2 style={{ marginBottom: 4 }}>New draft</h2>
        <p style={{ margin: 0, fontSize: "0.8125rem", color: "var(--rs-text-2)" }}>
          Start from a sample template (labelled sample — review before publishing) or edit an
          existing version on the left. Signed and stored via POST /v1/policies.
        </p>
      </div>

      <div className="rs-row" style={{ marginBottom: 12 }}>
        <div className="rs-field">
          <label htmlFor="template">Template</label>
          <select id="template" className="rs-select" value={template} onChange={(e) => setTemplate(e.target.value)}>
            {SAMPLE_PROFILES.map((s) => (
              <option key={s.name} value={s.document.profile}>
                {s.document.profile} (sample)
              </option>
            ))}
          </select>
        </div>
        <button
          type="button"
          className="rs-btn rs-btn--ghost rs-btn--sm"
          onClick={() => {
            const s = sampleByProfileName(template);
            if (s) setDoc(JSON.stringify(s.document, null, 2));
          }}
        >
          Load template
        </button>
      </div>

      {sample ? (
        <div className="rs-badge rs-badge--sample" style={{ marginBottom: 8 }}>
          <span className="dot" aria-hidden="true" /> sample · {sample.source}
        </div>
      ) : null}

      {schemaError ? (
        <div className="rs-toast" style={{ marginBottom: 10 }}>
          Schema endpoint unreachable; structural checks only until it responds.
        </div>
      ) : null}
      {parsed.ok && validation.valid ? (
        <div className="rs-toast rs-toast--ok" style={{ marginBottom: 10 }}>
          Valid against the policy schema.
        </div>
      ) : (
        <div className="rs-callout" style={{ marginBottom: 10 }}>
          <strong>{parsed.ok ? "Schema validation failed." : "Not valid JSON."}</strong>
          {!parsed.ok ? (
            <div className="rs-mono" style={{ fontSize: "0.75rem" }}>{parsed.error}</div>
          ) : (
            <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
              {validation.errors.slice(0, 10).map((e, i) => (
                <li key={i} className="rs-mono" style={{ fontSize: "0.75rem" }}>
                  <code>{e.path}</code> {e.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <textarea
        className="rs-textarea"
        style={{ minHeight: 240 }}
        aria-label="new policy document JSON"
        value={doc}
        onChange={(e) => setDoc(e.target.value)}
        spellCheck={false}
      />
      <div style={{ marginTop: 12 }}>
        <button
          type="button"
          className="rs-btn rs-btn--primary"
          disabled={!parsed.ok || !validation.valid}
          onClick={create}
        >
          Sign &amp; create draft
        </button>
      </div>
      <p style={{ fontSize: "0.7rem", color: "var(--rs-text-3)", margin: "8px 0 0" }}>
        {versions.length === 0
          ? "No versions yet for this organisation — this becomes v1."
          : `Will create v${Math.max(...versions.map((v) => v.version)) + 1} for ${org}.`}
      </p>
    </div>
  );
}

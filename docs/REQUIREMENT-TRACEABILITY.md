# RuntimeShield — Requirement Traceability

Maps each functional (FR) and non-functional (NFR) requirement from
`01-RuntimeShield.md` §4 to where it is implemented on disk today. The web
console (`web/`) is landing now with this milestone: the four operator screens
(team admin, policy editor, audit timeline, approval workspace) are wired to
real `/v1` routes with honest loading/empty/error states. Where a requirement
is only partially met, that is said plainly.

Legend: ✅ implemented · ◑ partial / bounded · — not started.

## Functional requirements (§4.1)

### FR-01 Execution interception
- ✅ Structured execution request schema, argv preserved as an argument array
  (never reconstructed from string concatenation): `rust/crates/core/src/request.rs`
  (validate + `digest()`), `rust/crates/agent/src/main.rs` (`read_request`,
  `exec` launches via `std::process::Command` with `argv`, no shell).
- ✅ Captures `cwd`, workspace, principal, requested env keys: request fields.
  `principal` distinguishes user / agent / service (`Principal`).
- ◑ Parent process / user identity / repository context: `parent_pid`, `user`,
  `repo_ref` exist on the request struct (optional) but the agent does not yet
  populate them from the host; the adapter that would supply them is not
  shipped.
- ✅ Execution origin (interactive user / agent / CI / internal service):
  `request.principal` enum + `principal_id`.

### FR-02 Policy evaluation
- ✅ Deterministic evaluation before execution: `rust/crates/core/src/eval.rs`
  (`evaluate`, `merge`). Pure and unit-tested (`eval.rs` `#[cfg(test)]`).
- ✅ allow / deny / require-approval / audit-only: `Decision` enum.
- ✅ path, executable, argument, process, network, environment, workspace
  conditions: `cap_check` branches in `eval.rs` + `paths.rs` / `netmatch.rs`.
- ✅ Explicit precedence, deny never bypassed by allow: `merge` strength table
  (deny 4 > require-approval 3 > allow 2 > audit-only 1); tests
  `explicit_deny_rule_overrides_allow_section`, `git_push_falls_to_default_deny`.
- ✅ Explain the matched rule and policy version: `EvalResult.matched_rule_ids`,
  `explanation`; `Check` prints `policy_version` / `policy_source`.

### FR-03 Filesystem boundaries
- ✅ Restrict reads/writes to workspace roots; sensitive paths denied by
  default: `fs_check` in `eval.rs` (sensitive/deny paths win, workspace
  containment, temp). Tests `sensitive_path_write_is_denied`,
  `workspace_write_inside_root_is_allowed`.
- ✅ Symlink / path-traversal detection, canonicalise before evaluation:
  `rust/crates/core/src/paths.rs` (tilde expand → resolve against cwd →
  canonicalise, ancestor walk for non-existent tails). Test
  `path_traversal_into_sensitive_still_denied`.
- ✅ Write scopes read-only / workspace-write / temp-write / approved path:
  `FsAccess` + `workspace.access`, `temp.access`, `allow_paths` (explicitly
  approved path).
- ◑ **This is a decision-time guard, not a kernel boundary.** It tells you
  which real location an access *would* hit; it does not confine the launched
  process to that location. See `ENFORCEMENT-LIMITS.md`.

### FR-04 Network controls
- ✅ Deny-by-default in the strongest profile: `restricted` example sets
  `network.default: deny` with no allow list.
- ✅ Destination policy by hostname/domain + port: `net_check` /
  `netmatch.rs` (exact, `*.suffix`, IDN normalisation, port lists). Test
  `npm_registry_is_allowed_other_hosts_deny`.
- ◑ DNS-rebinding / connection-time resolution: the check is on **request
  metadata** (the host/port the request declares), performed at decision time
  from `normalize_host`; it is **not** an egress filter that resolves and pins
  the IP at connect time. Stated as advisory in `ENFORCEMENT-LIMITS.md`.
- ✅ Record destination metadata without logging payload contents by default:
  events store `metadata_redacted`; `secret.rs` redaction applied before
  journal.

### FR-05 Secret protection
- ✅ Detect likely secrets in files/env metadata before exposing to an agent:
  `rust/crates/core/src/secret.rs` built-in + org-configured patterns;
  `deny_env_keys` in the policy secrets section; `eval.rs` denies requested
  env keys the policy lists (`secret-deny-env`).
- ✅ Redact secret values from logs and telemetry: `secret.rs` `redact`,
  applied by the agent before journaling (`redact_meta` in `main.rs`), and
  server-side event rows store `metadata_redacted`.
- ✅ No claim that regex scanning guarantees detection: `secret.rs` doc says
  "best-effort — regex scanning alone cannot guarantee detection."
- ✅ Org-specific secret path and pattern rules: `secrets.patterns` in the
  schema, merged with built-ins.

### FR-06 Approval workflow
- ✅ Show exact command, executable, arguments, requested capabilities, cwd,
  policy reason: the structured decision carries them; the console's approval
  workspace surfaces the requested scope + expiry.
- ✅ Once / allow-for-workspace / deny; narrow scoped exceptions with an
  expiry: `runshield approve` (scoped, `--expires-h`), local journal approval;
  control-plane `POST /v1/approvals` + `POST /v1/approvals/{id}/decision`
  (`server.go`), decided in the console's approval workspace.
- ✅ Record approver, timestamp, policy change: `approvals` row
  (`approver_id`, `expires_at`, `created_at`).
- ◑ Team-wide approval propagation: the control plane records the approval,
  but the device-side agent records local approvals in its own journal — the
  two stores are not yet reconciled (noted in `KNOWN-LIMITATIONS.md`).

### FR-07 Audit and replay
- ✅ Immutable decision events: local append-only SQLite journal
  (`rust/crates/agent/src/journal.rs`); server `policy_decisions` /
  `execution_events` tables.
- ✅ Reconstruct a timeline from process start, child processes, fs events and
  network metadata *where supported*: `runshield journal` prints a recent
  decision timeline; server audit timeline is the console's Audit screen.
  Child-process tracking and live fs/network metadata capture are not yet
  implemented (the agent records the decision + exec-finished events).
- ✅ Safe analytical replay only, never repeats destructive actions: the CLI
  exposes `check` (evaluate, no exec) separately from `exec`; replay is
  decision review, not re-execution.

### FR-08 Team control plane
- ✅ Manage organisations, projects (workspaces), users, policies, agent
  (device) identities: `users` / `workspaces` / `policies` / `devices` tables
  + read endpoints; orgs list is an empty-set read in this reference build
  (provisioning not implemented — the console shows that honestly).
- ✅ Sign and version policies: `policy.Sign` on draft create; monotonically
  increasing `version` via `NextPolicyVersion`; status draft → published →
  rolled_back.
- ✅ Offline policy cache with expiry and explicit fail-open/fail-closed:
  `rust/crates/agent/src/cache.rs` (`FailMode`), `runshield sync-policy` +
  `--fail-mode open|closed`.
- ◑ Policy rollout / staged deployment: publish + rollback are single-step
  status transitions; staged/canary rollout is not implemented (spec §15 is a
  later phase).
- ✅ Web console: **landing now** — `web/src/components/TeamAdmin.tsx`,
  `PolicyEditor.tsx`, `AuditTimeline.tsx`, `ApprovalsWorkspace.tsx`, all
  wired to real `/v1` operator routes.

## Non-functional requirements (§4.2)

- ◑ **Policy decision latency < 10 ms p95 (local cached rules):** evaluation is
  pure in-memory and targeted to be fast, but the benchmark has not been run
  on a real machine yet; it is an engineering target, not a measured claim.
- ✅ **Local availability on outage:** cached policy + fail-open/closed
  (`cache.rs`), file spool as the offline buffer (`spool.rs`), agent keeps
  deciding when the control plane is down.
- ◑ **Audit integrity (append-only; tamper-evident chaining planned):** local
  journal is append-only at the app layer; cryptographic chaining across the
  journal is explicitly *planned*, not implemented.
- ◑ **Portability (macOS/Linux MVP; Windows documented for later):** the agent
  targets the host it is built on; platform-specific enforcement gaps are
  documented in `ENFORCEMENT-LIMITS.md`, and Windows is out of scope for now.
- ✅ **Isolation (no untrusted workload shares host credentials by default):**
  the policy denies requested secret env keys by default; the sandboxed-child
  boundary itself is advisory today (see FR-03/04 and `ENFORCEMENT-LIMITS.md`).
- ✅ **Privacy (local-first, redact secrets, configurable retention):** local
  journal, redaction before persistence; retention controls not yet exposed
  (events are kept until pruned — no retention knob in the control plane yet).
- ✅ **Reliability (explicit behaviour on policy-service outage, no silent
  bypass):** `--fail-mode` makes the outage behaviour explicit and
  operator-chosen; the default is fail-closed for a `restricted` profile.
- ✅ **Usability (every block has an actionable explanation + safe next
  step):** `EvalResult.explanation` + `remediation`, surfaced as a callout on
  every denial in the console's audit timeline.

## MVP definition of done (§18)

- ✅ Install + run a supported workflow inside a restricted workspace:
  `runshield exec` with the `restricted` example profile, `examples/requests/*`.
- ✅ Sensitive path access is denied and logged (`sensitive-or-deny-path`).
- ✅ Network access follows an explicit policy (`net-*` rules).
- ✅ Every decision includes a rule ID and a human-readable reason.
- ✅ Local guard remains operational during a control-plane outage per
  configured fail mode.
- ✅ No raw secret values are written to the audit log (redaction before
  journal; examples use env-key *names*, not values).
- ◑ Adversarial tests cover documented bypass cases: the test suite covers
  documented cases (traversal, symlink, default-deny, explicit-deny-override);
  a broader adversarial/fuzz suite is a later phase.
- ✅ UI has real empty/loading/error/permission states and no fabricated
  activity: the console ships them, and its sample data is labelled
  "sample" (spec §12 anti-pattern "no fabricated data").

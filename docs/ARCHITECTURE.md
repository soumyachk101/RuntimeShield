# RuntimeShield — Architecture

RuntimeShield is a policy-enforcing execution-security layer for AI coding
agents. It observes and controls what an agent can do at runtime: which
commands it can execute, which files it can read or modify, which network
destinations it can reach, which processes it can spawn, and which secrets it
may access. The design is local-first: the enforcement decision is made on the
device, not in a cloud, and the cloud (control plane) is optional for local
use.

This document describes the three on-disk components and how data flows
between them.

## Components

| Component | Location | Role | Trust level |
|---|---|---|---|
| Rust agent | `rust/` (workspace `runtime-shield-agent`, binary `runshield`) | Local enforcement: schema-validate execution requests, evaluate policy deterministically, journal decisions, upload events | **Trusted enforcement component** — owns the security-critical path |
| Go control plane | `controlplane/` | Team metadata, signed policy distribution, device enrolment, event ingestion, the console's read/operate API | Trusted distribution & audit service |
| Web console | `web/` | React + TypeScript operator UI: team admin, policy editor, audit timeline, approval workspace | Presentation only — never on the enforcement path |

Supporting pieces:

- `policies/schema/policy.schema.json` — the single JSON-Schema source of
  truth for policy documents. Both the Go policy service (server-side
  validation) and the web editor (client-side, fetched via
  `GET /v1/policies/schema`) validate against the same document.
- `examples/` — three sample policy profiles (`repository-development`,
  `restricted`, `inspect-only`) and three structured execution requests. The
  console ships the profiles as "sample" templates; the request files are
  fixtures for the agent CLI.
- `controlplane/migrations/001_init.sql` — canonical Postgres DDL; the app
  also self-applies an embedded idempotent subset on boot
  (`store.ApplySchema`), so SQLite dev runs need no external tooling.

The architecture decision that shapes everything else (spec §5 "Important
architecture decision"): **the Rust agent owns local enforcement and must not
depend on the control plane for every decision.** The Go control plane never
evaluates a security decision — its handlers only distribute policy, record
metadata and ingest audit events. The security-critical path lives entirely in
the Rust agent. Placing enforcement inside the web UI or an LLM service is
explicitly out of scope.

## Data flow (spec §6)

```
AI coding agent / CI task / developer CLI
                |
        Adapter / exec shim (adapter not yet shipped)
                |
       Rust runshield agent   (local, trusted)
        |        |         |
   Policy     Filesystem   Network/process
   evaluator  guard        guard      (all in-crate, deterministic)
        |        |         |
        +---- execution boundary ----+
                       |
             Local audit journal (SQLite, ~/.runshield/journal.db)
                       |
             Async event uploader (POST /v1/events/batch, idempotent)
                       |
             Go control-plane API
                |            |
           PostgreSQL     NATS JetStream   (NATS transport is a documented
                |            |                 reference; not yet consumed)
          Policy service   Event workers
                |            |
           Signed policy   Audit pipeline
                +----- Web console -----+
```

Walk-through of a single execution request:

1. An adapter (or the agent CLI `check`/`exec` commands, today) produces a
   structured execution request: `request_id`, `executable`, structured
   `argv` array, `cwd`, `workspace`, requested capabilities, requested env
   keys, principal. **argv is always an argument array; the agent never
   reconstructs a shell command from string concatenation.**
2. The agent validates the request against the execution-request schema
   (`rust/crates/core/src/request.rs`), normalises executable and path data.
3. It identifies the workspace and execution profile, resolving the policy to
   use: an explicit `--policy` file, or the cached signed policy from the
   control plane (`GET /v1/devices/{id}/policy`), with a configured
   fail-open / fail-closed behaviour when the cache is stale or missing.
4. The policy engine (`rust/crates/core/src/eval.rs`) evaluates
   executable, arguments, filesystem, network and process capabilities
   deterministically. Precedence is fixed: explicit deny rule > section deny
   > require-approval > allow > audit-only > profile default. Deny can never
   be bypassed by a broad allow.
5. The outcome is a structured decision: `decision` (allow / deny /
   require-approval / audit-only), matched rule IDs, an explanation, a safe
   remediation string (on denials), a permitted scope (on approvals) and an
   audit event ID. **No language model is the authoritative evaluator**; an
   AI explanation may summarise a decision but cannot override it.
6. If allowed, `exec` launches the process via structured `argv` (no shell),
   in the current reference build without an OS sandbox — see
   `ENFORCEMENT-LIMITS.md` for what that guarantees vs what is advisory.
7. The decision and lifecycle events are written to the local append-only
   journal with secret redaction applied, and spooled for upload.
8. When the control plane is reachable, the uploader drains the spool with
   `POST /v1/events/batch` (idempotency-keyed, so a crash-and-replay cannot
   double-count). The agent keeps working through a control-plane outage;
   the spool is the durable offline buffer.
9. The control plane persists redacted events and team metadata, publishes
   signed, versioned policies, and serves the web console's operator API.

## Trust boundaries (spec §6)

1. **Agent process (requester):** untrusted. A compromised AI agent can
   submit any request; every request is schema-validated and policy-evaluated
   before anything runs.
2. **`runshield` local agent:** the trusted enforcement component. It must
   not be bypassable by the workload it guards.
3. **Sandbox / isolation layer:** isolated execution environment for
   allowed workloads. In the current reference build this boundary is *not
   yet OS-enforced* — the agent gates the decision and journals it, but the
   launched child inherits the host environment. Documented, not claimed.
4. **Control plane:** trusted policy distribution and audit service. It signs
   policies and issues short-lived device tokens; a stolen token has a short
   TTL and is scoped to a device/org.
5. **External network:** untrusted unless explicitly allowed by policy.

A compromised agent must not be able to rewrite the policy cache, disable the
guard, or forge a trusted audit identity. The policy cache is written atomically
with `0600` perms and carries a signature the agent can verify
(`RUNSHIELD_POLICY_KEY`); the journal is a local SQLite store; audit rows on the
server are keyed by device and carry a `request_id` chain so a forged device
identity is detectable in the timeline. (Tamper-evident chaining across the
journal is planned, not yet implemented — see `KNOWN-LIMITATIONS.md`.)

## Policy model

Policies are versioned JSON documents validated against
`policies/schema/policy.schema.json` (JSON Schema 2020-12). The core
sections: `filesystem` (workspace roots, temp, sensitive/deny/allow paths),
`network` (default allow/deny plus host:port allow & deny lists), `process`
(allow / require-approval / deny lists of executable + actions), `secrets`
(denied env-key names and org-configured redaction patterns) and a top-level
`rules` array of explicit, id'd, capability-scoped overrides that take
precedence over the section lists.

The engine's explicit rule IDs are product-defined; the section rules carry
stable built-in ids (`net-default-deny`, `fs-workspace`,
`proc-require-approval`, `secret-deny-env`, …) plus the matched rule's note.
Every denial carries a matched rule ID, a human-readable explanation and a
safe remediation string — the engine produces all three; the UI just
surfaces them.

## Versioning

Policy schema version, agent protocol version, and the policy document's
`policy_version` label are versioned independently (spec §15). A device
fetches only the latest **published** policy for its organisation; drafts are
invisible to devices. `GET /v1/devices/{id}/policy` returns `document: null`
with a note when nothing is published, telling the agent to keep its cache.

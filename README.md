# RuntimeShield

A policy-enforcing execution-security layer for AI coding agents and developer
automation. RuntimeShield observes and controls what an agent can do at
runtime — which commands it can execute, which files it can read or modify,
which network destinations it can reach, which processes it can spawn and
which secrets it may access. It enforces controls at the process boundary
(deterministic, auditable policy decisions made **before** execution), never
by inspecting prompts or asking an LLM whether a command is safe.

**Core promise:** use powerful coding agents while limiting the blast radius
of unsafe, compromised or misconfigured tool execution. Default-deny for
sensitive capabilities, with explicitly approved, expiring exceptions, and an
explanation (rule id + safe remediation) on every block.

This repo holds the product in three components plus shared assets. The web
console is landing with this milestone; the other two are complete.

## Components

| Component | Path | Language | What it is |
|---|---|---|---|
| Local agent | `rust/` | Rust | The trusted enforcement component. Schema-validates execution requests, evaluates policy deterministically, journals decisions, and uploads events. Binary `runshield`. |
| Control plane | `controlplane/` | Go | Team metadata, signed policy distribution, device enrolment, event ingestion, and the operator API the console calls. |
| Web console | `web/` | TypeScript + React | Operator UI: team admin, policy editor, audit timeline, approval workspace. |
| Policy schema | `policies/schema/policy.schema.json` | JSON | The single source of truth both the Go policy service and the web editor validate against. |
| Examples | `examples/` | JSON | Three sample policy profiles and three structured execution requests. |

See `docs/ARCHITECTURE.md` for the data flow, trust boundaries and the
enforcement decision that shapes all three (the Rust agent owns enforcement;
the control plane and UI never make a security decision).

## Install / run

### Rust agent (`cargo`)

```sh
cd rust
cargo build --release        # → target/release/runshield
cargo test                   # core + agent test suites

# Evaluate an example request against an example policy (no shell is spawned):
cargo run -p runtime-shield-agent -- check examples/requests/git-status.json \
    --policy examples/policy-repository-development.json
```

Agent-side env vars (see `rust/crates/agent/src/main.rs`):

- `RUNSHIELD_CONTROL_PLANE` — control-plane base URL (policy pull / event upload).
- `RUNSHIELD_DATA_DIR` — data directory (default `~/.runshield`).
- `RUNSHIELD_POLICY_KEY` — hex key material for verifying policy signatures.

The agent is distributed as a **signed local binary, not a container image** —
`infrastructure/AGENT-RELEASE-NOTES.md` explains why and documents the host
binary layout.

### Go control plane (`go`)

```sh
cd controlplane
cp .env.example .env         # keep RUNSHIELD_BACKEND=sqlite for a zero-dependency dev run
go run ./cmd/controlplane    # listens on :8080 (RUNSHIELD_HTTP_ADDR)
```

For Postgres: `RUNSHIELD_BACKEND=postgres` + `RUNSHIELD_PG_DSN`
(`postgres://user:pass@localhost:5432/runshield`). The app applies its schema
on boot; the canonical DDL is `controlplane/migrations/001_init.sql`
(documented in `infrastructure/MIGRATIONS.md`). Health:
`curl http://localhost:8080/v1/healthz`.

> **Note:** the control plane does not compile in its current on-disk state
> (`internal/api` has an undefined-variable gap noted in
> `deploy/NOTES-AND-GAPS.md`), and `go.sum` is not committed. Run the Go
> commands above after that gap is resolved; the README documents the intended
> interface, not a green build.

### Web console (`npm` dev server)

```sh
cd web
npm install
npm run dev                 # vite on :5173, proxies /v1 -> :8080
npm run typecheck && npm run build
```

The dev proxy target is `RUNSHIELD_CONTROL_PLANE` (default
`http://localhost:8080`) in `web/vite.config.ts`; the console is same-origin
and never embeds a control-plane address. Fonts are self-hosted via the
`@fontsource/geist-sans` / `@fontsource/geist-mono` packages (imported in
`web/src/main.tsx`); binary font files are not vendored in the repo.

## Environment reference

Control-plane vars (`controlplane/internal/config/config.go`):

| Var | Default | Meaning |
|---|---|---|
| `RUNSHIELD_BACKEND` | `sqlite` | `sqlite` (embedded, no service) or `postgres`. |
| `RUNSHIELD_SQLITE_PATH` | `data/runshield.db` | SQLite file for the embedded backend. |
| `RUNSHIELD_PG_DSN` | — | Postgres DSN, required when `RUNSHIELD_BACKEND=postgres`. |
| `RUNSHIELD_HTTP_ADDR` | `:8080` | Listen address. |
| `RUNSHIELD_TLS_CERT` / `RUNSHIELD_TLS_KEY` | — | TLS, optional (omit for plain-HTTP dev). |
| `RUNSHIELD_SIGN_KEY` | — | 32-byte hex key for policy signatures + device tokens. Ephemeral in dev, mandatory in prod. |
| `RUNSHIELD_SESSION_KEY` | — | 32-byte hex key for operator session tokens. |
| `RUNSHIELD_RATE_LIMIT_RPS` / `RUNSHIELD_RATE_LIMIT_BURST` | `50` / `100` | Device-route rate limit. |
| `RUNSHIELD_LOG_LEVEL` | `info` | `debug\|info\|warn\|error`. |
| `RUNSHIELD_NATS_URL` | — | **Read but unconsumed today** (documented reference; see `docs/KNOWN-LIMITATIONS.md` #1). |
| `RUNSHIELD_POLICY_SCHEMA` | `policies/schema/policy.schema.json` | Path to the JSON schema the policy service validates against. |

Agent vars are `RUNSHIELD_CONTROL_PLANE`, `RUNSHIELD_DATA_DIR`,
`RUNSHIELD_POLICY_KEY` (above). A populated `.env` must never be committed;
generate the two key-material vars with `openssl rand -hex 32`.

## Local development (no containers)

The dev default is fully self-contained: SQLite backend, file spool, no NATS.

1. **Control plane** — `cd controlplane && go run ./cmd/controlplane`
   (SQLite fallback, creates `data/runshield.db`, applies schema on boot).
2. **Console** — `cd web && npm install && npm run dev` (vite proxies
   `/v1` to `:8080`).
3. **Agent** — `export RUNSHIELD_CONTROL_PLANE=http://localhost:8080` then
   `cargo run -p runtime-shield-agent -- check <request> --policy <policy>`.

No Postgres or NATS is required. Decisions journal to
`~/.runshield/journal.db`; the spool drains on `runshield upload` (or stays
put while offline).

## Compose smoke test

`docker-compose.yml` stitches the control plane (Postgres) and the console
(node → nginx, host port **8081**) into one stack. The one-command smoke test
from `deploy/GUIDE.md` is:

```sh
docker compose up -d --build && curl -fsS http://localhost:8081/v1/healthz
# expects  {"status":"ok","backend":"postgres",...}
```

This path exercises the web build, the nginx `/v1/` proxy, the control plane
and Postgres in one call. **It is quoted here, not claimed to pass** —
`deploy/NOTES-AND-GAPS.md` lists what blocks the compose build today (a Go
compile gap and, until this milestone, the missing web entry point). Read that
file before running the compose stage.

## Docs

- `docs/ARCHITECTURE.md` — components, data flow, trust boundaries, policy model.
- `docs/REQUIREMENT-TRACEABILITY.md` — every spec FR/NFR mapped to code, with what is landing now.
- `docs/ENFORCEMENT-LIMITS.md` — exactly what is guaranteed vs advisory on this OS; why no shell wrapper / prompt-level check is host security.
- `docs/KNOWN-LIMITATIONS.md` — what is not yet true on disk (NATS no-op, DDL-only migration, unvendored fonts, audit-ingestion gap, …).
- `infrastructure/MIGRATIONS.md` — Postgres migration + SQLite dev path.
- `infrastructure/AGENT-RELEASE-NOTES.md` — why the agent is a signed local binary, not an image.
- `deploy/GUIDE.md` + `deploy/NOTES-AND-GAPS.md` — staged deployment and the authoritative packaging-gap list.

## MVP status

What is **verified** (on disk, with tests) versus what is **landing** with
this milestone:

- ✅ **Verified:** deterministic policy evaluation with fixed precedence,
  canonicalised path checks, host/port decision matching, secret redaction
  before journal, offline spool + fail-open/closed cache — the Rust core has
  unit tests (`cargo test`) covering allow/deny/traversal/default-deny.
- ✅ **Verified (interface, not green build):** the Go control plane's full
  `/v1` route table (device enrol, policy publish/rollback/schema, decisions,
  approvals, events). The operator routes the console calls are present in
  `controlplane/internal/api/server.go`; the package has an outstanding
  compile gap to fix first.
- 🔵 **Landing now:** the web console — four screens wired to real `/v1`
  routes with honest loading/empty/error/permission states, schema-validated
  policy editing, a version diff, and the example-profiles carousel. Type
  checking and the build are the validation gate.
- ◑ **Documented, not yet built:** the OS-enforced isolation layer
  (seccomp/landlock/gVisor/Firecracker) around an allowed child — the current
  `exec` is advisory at the process boundary (`docs/ENFORCEMENT-LIMITS.md`).

Honest boundaries, not marketing: no shell wrapper, no LLM-as-evaluator, no
guarantee against a privileged adversary. `docs/ENFORCEMENT-LIMITS.md` is the
canonical statement.

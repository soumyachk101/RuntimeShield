# RuntimeShield — Packaging Notes & Gaps

Real, specific findings from building the packaging against the code as it
stands. Nothing here is a placeholder; each item names the file and line.
**The rule followed: none of these was fixed in code — the packaging is
written against what exists today, and the code-side fixes are deferred to the
owners (in-flight web head / main head).**

## Blocking (docker compose up will not fully work until these land)

1. **`internal/api` does not compile — undefined `n`.**
   `controlplane/internal/api/server.go:226-231`: after the first
   `writeJSON(...)` in `eventsBatch`, there is a second `if err != nil` block
   and a `s.Logger.Info("events batch", "received", len(b.Events), "new", n,
   ...)` referencing an undefined variable `n`. The package (and therefore the
   whole control plane) cannot build until this is deleted or reworked.
   → **The `controlplane` Dockerfile will fail at `go build` until the main
   head fixes `server.go`. No packaging workaround can hide this.**

2. **Web entry point missing — `npm run build` will fail.**
   `web/index.html:14` loads `/src/main.tsx`, but `web/src/main.tsx` does not
   exist; `web/src/screens/`, `web/src/components/`, `web/src/styles/` are
   empty. The other head is finishing the console. Until `main.tsx` lands,
   the `web/Dockerfile` build stage fails at `tsc -b` / `vite build`.
   → Packaging assumes the console will build to `web/dist/` (vite default).

## Non-blocking, but you must know (packaging written around these)

3. **No `controlplane/go.sum` in the repo.** `go.mod` declares its requires
   but the lock file is not committed, so a plain `go build` cannot run in an
   image. `controlplane/Dockerfile` works around it with
   `go mod download && go build -mod=mod` (populates and resolves hashes at
   build time). Once `go.sum` is committed, switch the Dockerfile to a pinned
   `COPY go.mod go.sum` + `go mod download` for reproducible builds.

4. **`RUNSHIELD_NATS_URL` is read but not consumed.**
   `controlplane/internal/config/config.go:28,86` loads it into
   `Config.NATSURL`; `internal/events` documents a NATS path (§5) but
   `events.go`'s `Ingest` only persists to the DB and dedupes in memory.
   Nothing publishes to JetStream yet. Hence `nats` in
   `docker-compose.yml` is a **documented reference service behind the
   `nats` profile, not a live dependency** — the default stack runs without it,
   on the product's file-spool fallback.

5. **API prefix is `/v1/`, not `/api/`.** The deployment brief anticipated an
   `/api/` reverse proxy. The actual console client (`web/src/lib/api.ts:15`,
   `const BASE = "/v1"`) and every control-plane route
   (`controlplane/internal/api/server.go:60-90`: `/v1/healthz`, `/v1/devices/`,
   `/v1/events/batch`, …) use `/v1/`. `deploy/nginx.conf` therefore forwards
   `/v1/` → `controlplane:8080`. If the web head later switches the base to
   `/api/`, change one line in `deploy/nginx.conf`.

6. **Postgres role/DB come from the compose env, not the migration.**
   `controlplane/migrations/001_init.sql` is `CREATE TABLE`/`INDEX` DDL only
   (header says "PostgreSQL 14+"). It never creates a role or database. So
   `POSTGRES_DB=runshield` / `POSTGRES_USER=runshield` in `docker-compose.yml`
   follow the convention in `controlplane/.env.example`'s example DSN
   (`postgres://user:pass@localhost:5432/runshield`), not something the
   migration hardcodes. The app also self-applies its embedded schema on boot
   (`cmd/controlplane/main.go:59`, `store.ApplySchema`), so the canonical
   migration file matters for managed-DB tooling, not for the compose bring-up.

7. **Key material is intentionally unset in the default compose stack.**
   config.go (`config.go:88-103`): `RUNSHIELD_SIGN_KEY` /
   `RUNSHIELD_SESSION_KEY` are optional in dev (the control plane falls back
   to a random ephemeral key and logs a warning that tokens won't survive a
   restart), mandatory in production. The compose file leaves them commented
   out with generate-and-inject instructions; see `deploy/GUIDE.md` Stage 2.

8. **Examples contain no real secrets (checked).**
   `examples/requests/*.json` use only env-var **key names** (`AWS_ACCESS_KEY_ID`,
   `GITHUB_TOKEN`, `OPENAI_API_KEY`, …) as *deny-list patterns* and demo
   fixtures (`evil.example`, `~/.ssh/id_rsa` as a path literal). No secret
   values. The root `.dockerignore` still excludes `examples/` from image
   builds (not a build input) — stated here so the exclusion reads as
   intentional, not as a secret-hygiene panic.

## Verified: what the packaging relies on (all confirmed in code)

| Claim | Evidence |
| --- | --- |
| Control plane listens on `:8080` by default | `config.go:59` (`HTTPAddr: ":8080"`), `main.go:111` |
| Health-check endpoint exists at `/v1/healthz` | `server.go:60,80,108` (returns `status`, `backend`, `nats`) |
| Backend switch is `RUNSHIELD_BACKEND=postgres` + `RUNSHIELD_PG_DSN` | `config.go:17-18,70-76`; `store.go:66-68` |
| Schema file is `policies/schema/policy.schema.json`, read from CWD by default, overridable via `RUNSHIELD_POLICY_SCHEMA` | `main.go:64-70` → baked into image at `/app/...` |
| Go 1.22 toolchain | `controlplane/go.mod:3` (`go 1.22`); deps are pure-Go (modernc.org/sqlite, pgx) → `CGO_ENABLED=0` works |
| Web is npm (not pnpm/yarn): no lockfile, no `packageManager` field | `web/package.json` (scripts only), absence of `pnpm-lock.yaml` / `yarn.lock` / `package-lock.json` |
| Web build output dir is `dist` | `vite` default; `web/.gitignore` pattern `web/dist/` (root `.gitignore:14`) |
| Dev proxy target convention | `web/vite.config.ts:11` (`/v1` → `RUNSHIELD_CONTROL_PLANE` default `http://localhost:8080`) |
| Agent env vars for host distribution | `rust/crates/agent/src/main.rs`: `RUNSHIELD_CONTROL_PLANE`, `RUNSHIELD_DATA_DIR` (default `~/.runshield`), `RUNSHIELD_POLICY_KEY` |
| Agent binary name / release profile | `rust/crates/agent/Cargo.toml` (`[[bin]] name = "runshield"`), `rust/Cargo.toml` (release: `lto=thin`, `strip=symbols`; `rusqlite` bundled → statically linkable) |
| Spec packaging channels (Homebrew / apt/deb / signed binaries) | `01-RuntimeShield.md` §5 "Packaging" row; §15 "Ship signed CLI/agent binaries" |

## Known limitations of the packaging as shipped

- `docker-compose.yml` maps the console to host **8081** (the control plane is
  deliberately off public mapping; it is only reachable through the nginx
  `/v1/` proxy or via the uncommented `ports:` block).
- `nats:latest` is a moving tag for the optional reference service; pin it
  before promoting the profile to production.
- `web/Dockerfile` runs `npm install` without a lockfile, so the console
  build is not reproducible until the repo gains a `package-lock.json` (the
  web head owns that).
- No image for the Rust agent exists and none should (by design) —
  `infrastructure/AGENT-RELEASE-NOTES.md` documents signed local
  distribution instead.

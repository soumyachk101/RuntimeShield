# RuntimeShield — Deployment Guide

Staged: local dev (no containers) → single-host compose → managed-Postgres +
managed-NATS production split. Every env var name used below is the control
plane's own (`controlplane/internal/config/config.go`, `controlplane/.env.example`).

Companion files: `../docker-compose.yml`, `controlplane/Dockerfile`,
`web/Dockerfile`, `nginx.conf`, `NOTES-AND-GAPS.md` (read that first — it lists
things that block the compose stages today), `../infrastructure/AGENT-RELEASE-NOTES.md`
(why the Rust agent is *not* in any of this).

## Stage 0 — Staged local dev (no Docker, no external services)

The product's dev default is fully self-contained: SQLite backend, file spool,
no NATS.

1. **Control plane** (SQLite fallback — no DB server needed):
   ```sh
   cd controlplane
   cp .env.example .env      # keep RUNSHIELD_BACKEND=sqlite (the default)
   go run ./cmd/controlplane # listens on :8080 (RUNSHIELD_HTTP_ADDR)
   ```
   It creates `data/runshield.db` (RUNSHIELD_SQLITE_PATH) and applies the
   embedded schema on boot. `curl http://localhost:8080/v1/healthz` →
   `{"status":"ok","backend":"sqlite",...}`.

2. **Console** (in dev, the web head's territory until it lands; shape is):
   ```sh
   cd web
   npm install
   npm run dev               # vite on :5173, proxies /v1 -> :8080
   ```
   Vite proxies `/v1` to `RUNSHIELD_CONTROL_PLANE` (default
   `http://localhost:8080`) — that is why the console has no API URL baked in.

3. **Agent** (local host binary, run where the developer works):
   ```sh
   export RUNSHIELD_CONTROL_PLANE=http://localhost:8080
   cargo run -p runtime-shield-agent -- check examples/requests/npm-install.json \
       --policy examples/policy-repository-development.json
   ```
   Decisions journal to `~/.runshield/journal.db`; the spool drains on
   `runshield upload` (or stays put while offline — the no-op fallback).

At no point in Stage 0 is Postgres or NATS required.

## Stage 1 — Single-host compose (this repo's `docker-compose.yml`)

Preconditions: see `NOTES-AND-GAPS.md` — two items block the build today
(`internal/api` compile gap; web entry point), both owned by in-flight work.

```sh
docker compose up -d --build
```

Resulting topology (from `../docker-compose.yml`):

| service        | image / build                              | host port | role |
| -------------- | ------------------------------------------ | --------- | ---- |
| `web`          | `web/Dockerfile` (node → nginx)            | **8081**  | console UI + reverse proxy |
| `controlplane` | `controlplane/Dockerfile` (golang → distroless) | — (internal) | Go API, `RUNSHIELD_BACKEND=postgres` |
| `postgres`     | `postgres:16`                              | — (internal) | team metadata, db+user `runshield` |
| `nats`         | `nats` (profile `nats`)                    | 4222      | JetStream reference, **optional** |

- The control plane is **not** port-mapped; reach it through the web front:
  `http://localhost:8081/v1/...`. Uncomment the `ports:` block in the compose
  file for direct testing.
- `postgres` credentials follow `.env.example`'s DSN convention
  (`POSTGRES_DB=runshield`, `POSTGRES_USER=runshield`); `migrations/001_init.sql`
  is table DDL only — the role/DB are provisioned by the compose env vars, and
  the app additionally auto-applies its embedded schema on boot.
- **NATS is optional** (`docker compose --profile nats up -d`): it is a
  documented reference for the spec's JetStream transport. Nothing in today's
  code consumes `RUNSHIELD_NATS_URL` yet — the events pipeline is DB-persist
  + file-spool fallback — so the default stack runs correctly without it.
- **Smoke test** (one command; run after the web entry point lands):
  ```sh
  docker compose up -d --build && curl -fsS http://localhost:8081/v1/healthz
  ```
  Expects `{"status":"ok","backend":"postgres",...}` — that path exercises the
  web build, the nginx `/v1/` proxy, the control plane and Postgres in one.

## Stage 2 — Production split (managed Postgres + managed NATS)

What changes versus Stage 1, service by service:

- **Control plane**: same image, different env.
  - `RUNSHIELD_BACKEND=postgres`
  - `RUNSHIELD_PG_DSN` → managed Postgres (RDS/Cloud SQL/etc.) with
    `sslmode=require`. DB/role of your choosing (the app only auto-creates
    tables; the canonical DDL is `controlplane/migrations/001_init.sql`, so
    keep it applied in your DB tooling — the embedded DDL is an idempotent
    subset, the migration file is canonical).
  - `RUNSHIELD_SIGN_KEY` / `RUNSHIELD_SESSION_KEY` **required in production**
    (config.go: "In production it is mandatory") — from your secret manager,
    `openssl rand -hex 32`, distinct per environment, never in the image.
  - `RUNSHIELD_TLS_CERT` / `RUNSHIELD_TLS_KEY` if terminating TLS on the
    service itself (otherwise terminate at the platform LB).
- **Postgres**: drop the `postgres` service and `postgres-data` volume; keep
  backups + tested restores (spec §15).
- **NATS**: replace the profiled `nats` service with managed NATS / NATS
  Cloud; set `RUNSHIELD_NATS_URL` (e.g. `nats://…:4222`). Note this is
  forward-looking until the publisher/worker path lands (gap in
  `NOTES-AND-GAPS.md`); retention + dead-letter per spec §15.
- **Web front**: same static + nginx build; put it behind your TLS terminator,
  and keep the `proxy_pass` target pointed at wherever the control plane now
  lives (update `deploy/nginx.conf` if the upstream address stops being the
  literal service name).
- **Agent**: no change — it is signed local distribution only
  (`../infrastructure/AGENT-RELEASE-NOTES.md`), pointed at your public
  control-plane URL via `RUNSHIELD_CONTROL_PLANE`. Never ship it as an image.

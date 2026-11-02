# RuntimeShield Control Plane — Scaling Notes

## Stateless API behind a load balancer

The API process is stateless: all durable state lives in the store
(SQLite file or Postgres), so any replica can serve any request. Put a
load balancer in front and scale horizontally.

Two caveats, stated plainly:

- **Per-replica rate limits.** The token buckets are in-memory, per
  replica. A client pinned to one replica sees that replica's budget;
  across N replicas the effective aggregate budget is N× the per-class
  limit, and each replica's counters reset independently when replicas
  are added/removed (a scale-out momentarily widens the global budget,
  a scale-in tightens it). If you need a strict cluster-wide budget,
  move the limiter to a shared store (Redis) — out of scope today.
- **Dedupe is per-replica too.** The event ingester's in-memory
  idempotency set is per process. Across replicas, a replayed batch may
  land on a different replica and be re-persisted; the dedupe window
  then only applies within one replica. The store's insert is still
  safe, the count just may not be.

## Storage: SQLite vs Postgres

- **SQLite (embedded, default) is NOT horizontal.** One process, one
  writer; only one control-plane replica can own the data file.
  Scale out requests behind a single SQLite-backed replica (vertical
  scaling, more CPU/connections), or move to Postgres.
- **Postgres is the multi-replica backend.** Run
  `RUNSHIELD_BACKEND=postgres` with `RUNSHIELD_PG_DSN`, apply
  `migrations/`, and any number of API replicas can share it. This is
  the shape for production.

## Probes

- `GET /v1/healthz` — liveness alias; returns a body even when degraded
  (the web topbar and the compose smoke test depend on the exact shape).
- `GET /v1/ready` — readiness gate; 503 until `Store.Ping()` succeeds,
  200 after. Point LB/health-checks at `/v1/ready`, liveness at
  `/v1/healthz`. `/v1/ready` is not rate-limited.

## Rate limits (per-class, per-replica)

One token bucket per class, per remote address, per replica:

| Class | Routes | Default RPS | Default burst | Env override |
|---|---|---|---|---|
| `events` | `POST /v1/events/batch` | 50 | 100 | `RUNSHIELD_RATE_EVENTS_RPS` / `RUNSHIELD_RATE_EVENTS_BURST` |
| `enrol` | `POST /v1/devices/enrol` | 5 | 10 | `RUNSHIELD_RATE_ENROL_RPS` / `RUNSHIELD_RATE_ENROL_BURST` |
| `heartbeat` | `POST /v1/devices/{id}/heartbeat` | 10 | 20 | `RUNSHIELD_RATE_HEARTBEAT_RPS` / `RUNSHIELD_RATE_HEARTBEAT_BURST` |
| `device` | `POST /v1/devices/{id}/token`, `GET /v1/devices/{id}/policy`, `GET /v1/healthz`, `GET /v1/workspaces/{id}/executions` | 20 | 40 | `RUNSHIELD_RATE_DEVICE_RPS` / `RUNSHIELD_RATE_DEVICE_BURST` |
| `operator` | policies, organizations, users, devices, decisions, approvals | 10 | 20 | `RUNSHIELD_RATE_OPERATOR_RPS` / `RUNSHIELD_RATE_OPERATOR_BURST` |

429 responses carry `Retry-After` and the shared error envelope
(`err_rate_limited`). The legacy `RUNSHIELD_RATE_LIMIT_RPS` /
`RUNSHIELD_RATE_LIMIT_BURST` env vars still validate and log at startup
but no longer drive a limiter — the per-class knobs above are the real
knobs.

## Payload caps

- `POST /v1/events/batch`: **500 rows and 1 MiB** — 413
  `err_payload_too_large` beyond either.
- `POST /v1/policies`: **1 MiB** document byte cap — 413
  `err_payload_too_large` beyond.
- Small JSON bodies (enrol, approvals): **16 KiB**.

## Event fan-out (NATS JetStream)

When `RUNSHIELD_NATS_URL` is set, the *intended* design (spec §5) is a
durable JetStream stream that downstream workers consume, decoupling
audit fan-out from the HTTP request path.

**Today this is a documented no-op gap, stated honestly:**
`internal/config` reads `RUNSHIELD_NATS_URL` into `Config.NATSURL` and
nothing else consumes it. `internal/events.Ingestor.Ingest` persists to
the store only (with an in-memory dedupe set); there is no publisher,
stream, or consumer in this codebase. The compose file's `nats`
service is a reference entry behind a profile, not a live dependency,
and its default profile is off. This matches
`docs/KNOWN-LIMITATIONS.md` item 1.

What *does* decouple agents from control-plane availability is the
Rust agent's offline file spool
(`rust/crates/agent/src/spool.rs` — durable outbox, redelivery on the
idempotency key, bounded retention), so agents keep running and catch
up after an outage even with no NATS.

## Auth model and its scaling consequences

- Dev-open mode (no `RUNSHIELD_OPERATOR_KEY`): zero-config, unauthed
  requests pass with a WARN log and an `X-RS-Dev-Mode: true` response
  header. Not for anything with a network boundary.
- Keyed mode (`RUNSHIELD_OPERATOR_KEY` set): operators present a
  short-lived operator token; devices present a short-lived device
  token (except the first enrol). Tokens are HMAC-signed with the
  key, so **verification is stateless** — any replica can verify any
  token, which is exactly what makes the LB + multiple-replicas setup
  above work without a shared session store.

## Server hygiene

`http.Server` is configured with `ReadHeaderTimeout` 10s,
`ReadTimeout` 30s, `WriteTimeout` 30s, `IdleTimeout` 2m,
`MaxHeaderBytes` 1 MiB. Every response carries
`X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. CORS
is `*` in dev mode and the `RUNSHIELD_CORS_ORIGINS` list otherwise.

# RuntimeShield — Migrations

Documenting the Postgres migration path and the SQLite dev path, alongside
`AGENT-RELEASE-NOTES.md`. This is a note, not a tool: the control plane
self-applies its schema on boot, so there is no `migrate` step to run.

## Canonical DDL: `controlplane/migrations/001_init.sql`

- **Target:** PostgreSQL 14+.
- **What it is:** DDL only — `CREATE TABLE IF NOT EXISTS` for the eight
  tables (`organizations`, `users`, `devices`, `policies`, `approvals`,
  `execution_requests`, `policy_decisions`, `execution_events`) plus their
  indexes. No data, no views, no roles/GRANTs.
- **Dialect note:** the file is written so Postgres 14+ accepts it; the
  embedded SQLite backend accepts a superset of the same DDL
  (`CREATE TABLE IF NOT EXISTS` + plain types), so one file documents both.
- **Conventions (from the file header):**
  - All timestamps are RFC3339 strings in UTC, stored as `TEXT` so SQLite and
    Postgres store them identically and lexicographic comparison is safe.
  - `rule_ids` / `metadata_redacted` are `TEXT` (digests and redacted blobs),
    not query keys — no JSONB indexes.
- **How it is applied:** **The app self-applies its embedded schema on boot.**
  `controlplane/internal/store` opens the configured backend and runs
  `ApplySchema()`, which executes the embedded idempotent DDL. The
  `001_init.sql` file is the canonical human-readable DDL; the running
  process is what actually creates the tables, so there is no separate
  `migrate` step to run.

## SQLite dev path

- The embedded development backend is `modernc.org/sqlite` (pure Go, no
  CGO), selected via `RUNSHIELD_BACKEND=sqlite` (the default) with
  `RUNSHIELD_SQLITE_PATH` (default `data/runshield.db`).
- It creates the same eight tables on boot (`ApplySchema`), and the store
  opens it with a single writer (`db.SetMaxOpenConns(1)`) so the append-only
  journal and audit tables have no concurrent-writer issues in dev.
- No external service, no migration tooling: `go run ./cmd/controlplane`
  with zero env vars works out of the box. This is why the reference
  deployment can offer a Postgres backend while the dev path stays
  zero-dependency.

## Operational notes

- **Idempotency / safety:** everything is `IF NOT EXISTS`, so re-running the
  DDL (manually against a managed DB, or on every boot) is a no-op against
  an existing schema. This keeps the "self-applies on boot" design safe
  across restarts.
- **No destructive ALTERs:** if a column is ever added or renamed, it must
  be an additive `ALTER TABLE ... ADD COLUMN` that remains compatible with
  both dialects — Postgres 14+ accepts it, and the SQLite backend accepts a
  superset of the same DDL. Raw SQL in `ApplySchema` must stay in the
  shared placeholder form: the store rewrites `?` to `$n` for Postgres.
- **Postgres role/DB are provisioned out-of-band.** `001_init.sql` never
  creates a role or database; in the compose stack that comes from the
  `POSTGRES_DB=runshield` / `POSTGRES_USER=runshield` env, following the
  convention in `controlplane/.env.example`. On a managed Postgres you create
  the DB/role in your tooling and keep the canonical DDL applied there.
- **The audit tables start empty.** `execution_requests`,
  `policy_decisions` and `execution_events` are created but only
  `execution_events` has an API write path today (see
  `docs/KNOWN-LIMITATIONS.md` #2); seeding decision rows is a manual SQL
  step until the ingest gap lands.
- **Audit ingestion gap (see `docs/KNOWN-LIMITATIONS.md` #2):** the tables
  `execution_requests` and `policy_decisions` exist in this DDL, but the
  `POST /v1/events/batch` ingest path today only writes `execution_events`.
  An ingest path that fills the decision/request rows (or a small seed SQL
  for the console's audit timeline) is an open gap — the schema is ready, the
  write path is not.

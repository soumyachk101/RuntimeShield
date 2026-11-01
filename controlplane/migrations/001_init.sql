-- RuntimeShield control-plane schema.
--
-- Target: PostgreSQL 14+. The embedded dev backend (SQLite) accepts a
-- superset of this DDL via CREATE TABLE IF NOT EXISTS, so the same
-- files document both backends.
--
-- Conventions:
--   - all timestamps are RFC3339 strings in UTC; keep them TEXT so
--     SQLite and Postgres store them identically and comparisons
--     remain lexicographic-safe.
--   - rule_ids / metadata are JSONB-free TEXT: they are digests and
--     redacted blobs, not query keys.

CREATE TABLE IF NOT EXISTS organizations (
  id        TEXT PRIMARY KEY,
  name      TEXT NOT NULL,
  plan      TEXT NOT NULL DEFAULT 'community',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id                     TEXT PRIMARY KEY,
  organization_id        TEXT NOT NULL,
  identity_provider_id   TEXT,
  role                   TEXT NOT NULL DEFAULT 'member',
  FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

CREATE TABLE IF NOT EXISTS devices (
  id             TEXT PRIMARY KEY,
  organization   TEXT NOT NULL,
  public_key     TEXT NOT NULL,
  platform       TEXT NOT NULL,
  agent_version  TEXT,
  last_seen_at   TEXT,
  FOREIGN KEY (organization) REFERENCES organizations (id)
);
CREATE INDEX IF NOT EXISTS idx_devices_org ON devices (organization);

CREATE TABLE IF NOT EXISTS policies (
  id              TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  version         INTEGER NOT NULL,
  document        TEXT NOT NULL,
  signature       TEXT,
  status          TEXT NOT NULL DEFAULT 'draft',
  created_at      TEXT NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations (id)
);
CREATE INDEX IF NOT EXISTS idx_policies_org_status ON policies (organization_id, status);

CREATE TABLE IF NOT EXISTS approvals (
  id           TEXT PRIMARY KEY,
  request_id   TEXT NOT NULL,
  approver_id  TEXT NOT NULL,
  scope        TEXT NOT NULL,
  expires_at   TEXT,
  status       TEXT NOT NULL DEFAULT 'pending',
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_request ON approvals (request_id, status);

CREATE TABLE IF NOT EXISTS execution_requests (
  id            TEXT PRIMARY KEY,
  device_id     TEXT NOT NULL,
  workspace_id  TEXT NOT NULL,
  executable    TEXT NOT NULL,
  argv_digest   TEXT NOT NULL,
  cwd_digest    TEXT,
  requested_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exec_requests_device ON execution_requests (device_id, requested_at);

CREATE TABLE IF NOT EXISTS policy_decisions (
  id             TEXT PRIMARY KEY,
  request_id     TEXT NOT NULL,
  decision       TEXT NOT NULL,
  rule_ids       TEXT NOT NULL DEFAULT '[]',
  policy_version TEXT NOT NULL,
  decided_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_request ON policy_decisions (request_id, decided_at);

CREATE TABLE IF NOT EXISTS execution_events (
  id                 TEXT PRIMARY KEY,
  request_id         TEXT NOT NULL,
  event_type         TEXT NOT NULL,
  metadata_redacted  TEXT NOT NULL DEFAULT '{}',
  sequence           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_request ON execution_events (request_id, sequence);

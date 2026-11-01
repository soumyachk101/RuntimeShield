// Package store provides team-metadata persistence for the control
// plane. Two backends implement the same [Store]:
//
//   - embedded SQLite (modernc.org/sqlite, pure Go, no CGO): the local
//     development backend. Runs without any external service.
//   - PostgreSQL via pgx/stdlib: the production target. The migration
//     SQL in /migrations defines the schema; the repository methods
//     rewrite placeholders to `$n` so one codebase serves both.
//
// The interface is deliberately narrow: policy distribution,
// device/org/user management, approvals and audit ingestion.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Store is the backend-agnostic interface.
type Store interface {
	Ping() error
	// ApplySchema creates the tables if missing (idempotent). The
	// canonical DDL for Postgres is migrations/001_init.sql; the
	// embedded subset covers the same tables.
	ApplySchema() error
	Close() error
	Backend() string

	// Repositories
	UpsertOrg(ctx context.Context, o Org) error
	UpsertDevice(ctx context.Context, d Device) error
	Heartbeat(ctx context.Context, deviceID string) error
	ListDevices(ctx context.Context, org string) ([]Device, error)
	CreatePolicy(ctx context.Context, p Policy) error
	SetPolicyStatus(ctx context.Context, id, status string) error
	LatestPolicyForOrg(ctx context.Context, org string) (*Policy, error)
	ListPolicies(ctx context.Context, org string) ([]Policy, error)
	CreateApproval(ctx context.Context, a Approval) error
	SetApprovalStatus(ctx context.Context, id, status string) error
	PendingApprovals(ctx context.Context) ([]Approval, error)
	InsertExecutionRequest(ctx context.Context, r ExecutionRequest) error
	ListExecutionsForWorkspace(ctx context.Context, workspace string, limit int) ([]ExecutionRequest, error)
	InsertDecision(ctx context.Context, d Decision) error
	ListDecisions(ctx context.Context, limit int) ([]Decision, error)
	InsertEvent(ctx context.Context, e ExecEvent) error
}

// NewStore opens the configured backend.
func NewStore(backend, dsn, sqlitePath string) (Store, error) {
	var db *sql.DB
	var err error
	var kind string
	switch backend {
	case "sqlite":
		db, err = sql.Open("sqlite", sqlitePath)
		kind = "sqlite"
		if err == nil {
			db.SetMaxOpenConns(1) // single writer
		}
	case "postgres":
		db, err = stdlib.OpenDB(dsn)
		kind = "postgres"
	default:
		return nil, fmt.Errorf("unknown backend %q (want sqlite|postgres)", backend)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", backend, err)
	}
	return &dbStore{db: db, kind: kind}, nil
}

// dbStore implements Store.
type dbStore struct {
	db   *sql.DB
	kind string
}

func (s *dbStore) Ping() error     { return s.db.Ping() }
func (s *dbStore) Close() error    { return s.db.Close() }
func (s *dbStore) Backend() string { return s.kind }

func (s *dbStore) ApplySchema() error {
	script := `
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY, name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'community', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
  identity_provider_id TEXT, role TEXT NOT NULL DEFAULT 'member'
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, organization TEXT NOT NULL, public_key TEXT NOT NULL,
  platform TEXT NOT NULL, agent_version TEXT, last_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, version INTEGER NOT NULL,
  document TEXT NOT NULL, signature TEXT,
  status TEXT NOT NULL DEFAULT 'draft', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL, approver_id TEXT NOT NULL,
  scope TEXT NOT NULL, expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_requests (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL, workspace_id TEXT NOT NULL,
  executable TEXT NOT NULL, argv_digest TEXT NOT NULL,
  cwd_digest TEXT, requested_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_decisions (
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL, decision TEXT NOT NULL,
  rule_ids TEXT NOT NULL DEFAULT '[]', policy_version TEXT NOT NULL,
  decided_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_events (
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL, event_type TEXT NOT NULL,
  metadata_redacted TEXT NOT NULL DEFAULT '{}', sequence INTEGER NOT NULL DEFAULT 0
);
`
	_, err := s.db.Exec(s.rewrite(script))
	return err
}

// --- dialect helpers ---------------------------------------------------------

// rewrite turns `?` placeholders into `$n` on Postgres. It is a
// token scan, not a SQL parser; every query in this package uses `?`
// only in value position, which is the guarantee that makes this safe.
func (s *dbStore) rewrite(q string) string {
	if s.kind != "postgres" {
		return q
	}
	var out []byte
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			out = append(out, byte('$'))
			out = append(out, []byte(strconv.Itoa(n))...)
		} else {
			out = append(out, q[i])
		}
	}
	return string(out)
}

// nowRFC3339 keeps timestamp handling consistent across backends.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// exec runs a statement with values, dialect-aware.
func (s *dbStore) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.rewrite(q), args...)
}

// query runs a read, dialect-aware.
func (s *dbStore) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.rewrite(q), args...)
}

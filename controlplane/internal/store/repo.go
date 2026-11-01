// Package store repositories.
//
// All queries run through [dbStore.exec] / [dbStore.query], which
// rewrite `?` placeholders to `$n` on Postgres. The DDL in
// migrations/001_init.sql defines the shared schema;
// ApplySchema runs an idempotent subset so the embedded backend works
// with no external tooling.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Org mirrors the spec's Organization entity.
type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

// User mirrors User.
type User struct {
	ID                 string `json:"id"`
	OrganizationID     string `json:"organization_id"`
	IdentityProviderID string `json:"identity_provider_id"`
	Role               string `json:"role"`
}

// Device mirrors Device.
type Device struct {
	ID           string    `json:"id"`
	Organization string    `json:"organization"`
	PublicKey    string    `json:"public_key"`
	Platform     string    `json:"platform"`
	AgentVersion string    `json:"agent_version"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// Workspace mirrors Workspace.
type Workspace struct {
	ID            string `json:"id"`
	Organization  string `json:"organization_id"`
	RepositoryRef string `json:"repository_ref"`
	PolicyID      string `json:"policy_id"`
}

// Policy mirrors Policy.
type Policy struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"organization_id"`
	Version   int       `json:"version"`
	Document  string    `json:"document"`
	Signature string    `json:"signature"`
	Status    string    `json:"status"` // draft | published | rolled_back
	CreatedAt time.Time `json:"created_at"`
}

// Approval mirrors Approval.
type Approval struct {
	ID         string    `json:"id"`
	RequestID  string    `json:"request_id"`
	ApproverID string    `json:"approver_id"`
	Scope      string    `json:"scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	Status     string    `json:"status"` // pending | approved | denied | expired
	CreatedAt  time.Time `json:"created_at"`
}

// ExecutionRequest mirrors ExecutionRequest.
type ExecutionRequest struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"device_id"`
	WorkspaceID string    `json:"workspace_id"`
	Executable  string    `json:"executable"`
	ArgvDigest  string    `json:"argv_digest"`
	CwdDigest   string    `json:"cwd_digest"`
	RequestedAt time.Time `json:"requested_at"`
}

// Decision mirrors PolicyDecision.
type Decision struct {
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	Decision      string    `json:"decision"`
	RuleIDs       string    `json:"rule_ids"`
	PolicyVersion string    `json:"policy_version"`
	DecidedAt     time.Time `json:"decided_at"`
}

// ExecEvent mirrors ExecutionEvent.
type ExecEvent struct {
	ID               string `json:"id"`
	RequestID        string `json:"request_id"`
	EventType        string `json:"event_type"`
	MetadataRedacted string `json:"metadata_redacted"`
	Sequence         int64  `json:"sequence"`
}

// --- organizations -----------------------------------------------------------

func (s *dbStore) UpsertOrg(ctx context.Context, o Org) error {
	q := `INSERT INTO organizations (id, name, plan, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, plan = excluded.plan`
	_, err := s.exec(ctx, q, o.ID, o.Name, o.Plan, o.CreatedAt.Format(time.RFC3339))
	return err
}

// --- devices ------------------------------------------------------------------

func (s *dbStore) UpsertDevice(ctx context.Context, d Device) error {
	q := `INSERT INTO devices (id, organization, public_key, platform, agent_version, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			organization  = excluded.organization,
			public_key    = excluded.public_key,
			platform      = excluded.platform,
			agent_version = excluded.agent_version,
			last_seen_at  = excluded.last_seen_at`
	_, err := s.exec(ctx, q,
		d.ID, d.Organization, d.PublicKey, d.Platform, d.AgentVersion,
		d.LastSeenAt.Format(time.RFC3339))
	return err
}

func (s *dbStore) Heartbeat(ctx context.Context, deviceID string) error {
	q := `UPDATE devices SET last_seen_at = ? WHERE id = ?`
	res, err := s.exec(ctx, q, nowRFC3339(), deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("device %q not enrolled", deviceID)
	}
	return nil
}

func (s *dbStore) ListDevices(ctx context.Context, org string) ([]Device, error) {
	q := `SELECT id, organization, public_key, platform, agent_version, last_seen_at
		FROM devices WHERE organization = ? ORDER BY id`
	rows, err := s.query(ctx, q, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		var lastSeen string
		if err := rows.Scan(&d.ID, &d.Organization, &d.PublicKey, &d.Platform, &d.AgentVersion, &lastSeen); err != nil {
			return nil, err
		}
		d.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
		out = append(out, d)
	}
	return out, rows.Err()
}

// --- users --------------------------------------------------------------------

// ListUsers returns the members of an organisation. The reference build has
// no user-management writes; this is the read the console's team-admin
// screen needs (spec §4.1 FR-08: manage users).
func (s *dbStore) ListUsers(ctx context.Context, org string) ([]User, error) {
	q := `SELECT id, organization_id, identity_provider_id, role
		FROM users WHERE organization_id = ? ORDER BY id`
	rows, err := s.query(ctx, q, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		var idp sql.NullString
		if err := rows.Scan(&u.ID, &u.OrganizationID, &idp, &u.Role); err != nil {
			return nil, err
		}
		u.IdentityProviderID = idp.String
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- policies -----------------------------------------------------------------

func (s *dbStore) CreatePolicy(ctx context.Context, p Policy) error {
	q := `INSERT INTO policies (id, organization_id, version, document, signature, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.exec(ctx, q,
		p.ID, p.OrgID, p.Version, p.Document, p.Signature, p.Status,
		p.CreatedAt.Format(time.RFC3339))
	return err
}

// SetPolicyStatus transitions a policy (publish / rollback).
func (s *dbStore) SetPolicyStatus(ctx context.Context, id, status string) error {
	res, err := s.exec(ctx, `UPDATE policies SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("policy %q not found", id)
	}
	return nil
}

// LatestPolicyForOrg returns the most recent published policy for the
// organization, or nil if none exists.
func (s *dbStore) LatestPolicyForOrg(ctx context.Context, org string) (*Policy, error) {
	q := `SELECT id, organization_id, version, document, signature, status, created_at
		FROM policies
		WHERE organization_id = ? AND status = 'published'
		ORDER BY version DESC, created_at DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, s.rewrite(q), org)
	var p Policy
	var doc, sig, created string
	if err := row.Scan(&p.ID, &p.OrgID, &p.Version, &doc, &sig, &p.Status, &created); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	p.Document, p.Signature = doc, sig
	p.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return &p, nil
}

// ListPolicies returns an org's policies, newest first.
func (s *dbStore) ListPolicies(ctx context.Context, org string) ([]Policy, error) {
	q := `SELECT id, organization_id, version, document, signature, status, created_at
		FROM policies WHERE organization_id = ? ORDER BY version DESC, created_at DESC`
	rows, err := s.query(ctx, q, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		var p Policy
		var doc, sig, created string
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Version, &doc, &sig, &p.Status, &created); err != nil {
			return nil, err
		}
		p.Document, p.Signature = doc, sig
		p.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, p)
	}
	return out, rows.Err()
}

// --- approvals ----------------------------------------------------------------

func (s *dbStore) CreateApproval(ctx context.Context, a Approval) error {
	q := `INSERT INTO approvals (id, request_id, approver_id, scope, expires_at, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.exec(ctx, q,
		a.ID, a.RequestID, a.ApproverID, a.Scope,
		a.ExpiresAt.Format(time.RFC3339), a.Status,
		a.CreatedAt.Format(time.RFC3339))
	return err
}

func (s *dbStore) SetApprovalStatus(ctx context.Context, id, status string) error {
	res, err := s.exec(ctx, `UPDATE approvals SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("approval %q not found", id)
	}
	return nil
}

// PendingApprovals lists approvals awaiting a decision.
func (s *dbStore) PendingApprovals(ctx context.Context) ([]Approval, error) {
	q := `SELECT id, request_id, approver_id, scope, expires_at, status, created_at
		FROM approvals WHERE status = 'pending' ORDER BY created_at`
	rows, err := s.query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		var exp, created string
		if err := rows.Scan(&a.ID, &a.RequestID, &a.ApproverID, &a.Scope, &exp, &a.Status, &created); err != nil {
			return nil, err
		}
		a.ExpiresAt, _ = time.Parse(time.RFC3339, exp)
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- executions / decisions / events -----------------------------------------

func (s *dbStore) InsertExecutionRequest(ctx context.Context, r ExecutionRequest) error {
	q := `INSERT INTO execution_requests (id, device_id, workspace_id, executable, argv_digest, cwd_digest, requested_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO NOTHING`
	_, err := s.exec(ctx, q,
		r.ID, r.DeviceID, r.WorkspaceID, r.Executable, r.ArgvDigest, r.CwdDigest,
		r.RequestedAt.Format(time.RFC3339))
	return err
}

func (s *dbStore) ListExecutionsForWorkspace(ctx context.Context, ws string, limit int) ([]ExecutionRequest, error) {
	q := `SELECT id, device_id, workspace_id, executable, argv_digest, cwd_digest, requested_at
		FROM execution_requests WHERE workspace_id = ? ORDER BY requested_at DESC LIMIT ?`
	rows, err := s.query(ctx, q, ws, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExecutionRequest{}
	for rows.Next() {
		var r ExecutionRequest
		var at string
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.WorkspaceID, &r.Executable, &r.ArgvDigest, &r.CwdDigest, &at); err != nil {
			return nil, err
		}
		r.RequestedAt, _ = time.Parse(time.RFC3339, at)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *dbStore) InsertDecision(ctx context.Context, d Decision) error {
	q := `INSERT INTO policy_decisions (id, request_id, decision, rule_ids, policy_version, decided_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`
	_, err := s.exec(ctx, q, d.ID, d.RequestID, d.Decision, d.RuleIDs, d.PolicyVersion, d.DecidedAt.Format(time.RFC3339))
	return err
}

func (s *dbStore) ListDecisions(ctx context.Context, limit int) ([]Decision, error) {
	q := `SELECT id, request_id, decision, rule_ids, policy_version, decided_at
		FROM policy_decisions ORDER BY decided_at DESC LIMIT ?`
	rows, err := s.query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var d Decision
		var at string
		if err := rows.Scan(&d.ID, &d.RequestID, &d.Decision, &d.RuleIDs, &d.PolicyVersion, &at); err != nil {
			return nil, err
		}
		d.DecidedAt, _ = time.Parse(time.RFC3339, at)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *dbStore) InsertEvent(ctx context.Context, e ExecEvent) error {
	q := `INSERT INTO execution_events (id, request_id, event_type, metadata_redacted, sequence)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING`
	_, err := s.exec(ctx, q, e.ID, e.RequestID, e.EventType, e.MetadataRedacted, e.Sequence)
	return err
}

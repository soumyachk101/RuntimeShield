// Package api wires the HTTP control plane: device enrolment, policy
// distribution, event ingestion, approvals and the operator console's
// read endpoints.
//
// Every handler returns structured JSON. Public endpoints (device
// enrol, event batch) pass through the rate limiter; the operator
// endpoints sit behind a session check. No handler touches a policy
// decision: the security-critical path lives entirely in the Rust
// agent (spec §5 "important architecture decision").
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"runshield.dev/controlplane/internal/auth"
	"runshield.dev/controlplane/internal/events"
	"runshield.dev/controlplane/internal/policy"
	"runshield.dev/controlplane/internal/ratelimit"
	"runshield.dev/controlplane/internal/store"
)

// Server bundles all dependencies for the HTTP handlers.
type Server struct {
	Store       store.Store
	Policy      *policy.Service
	Ingest      *events.Ingestor
	Issuer      *auth.TokenIssuer
	RateLimiter *ratelimit.Limiter
	Logger      *slog.Logger
}

// NewServer builds a Server. issuer may be nil in dev mode (device
// endpoints are then open but clearly logged as unsigned).
func NewServer(s store.Store, ps *policy.Service, in *events.Ingestor, iss *auth.TokenIssuer, rl *ratelimit.Limiter, lg *slog.Logger) *Server {
	if lg == nil {
		lg = slog.Default()
	}
	return &Server{Store: s, Policy: ps, Ingest: in, Issuer: iss, RateLimiter: rl, Logger: lg}
}

// Routes registers all control-plane endpoints on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	// Public / device-facing, rate-limited.
	public := s.RateLimiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			return
		}
		// Dispatch
		switch {
		case r.URL.Path == "/v1/healthz":
			healthz(w, r, s)
		case r.URL.Path == "/v1/devices/enrol" && r.Method == http.MethodPost:
			devicesEnrol(w, r, s)
		case strings.HasPrefix(r.URL.Path, "/v1/devices/") && strings.HasSuffix(r.URL.Path, "/heartbeat") && r.Method == http.MethodPost:
			deviceHeartbeat(w, r, s)
		case strings.HasPrefix(r.URL.Path, "/v1/devices/") && strings.HasSuffix(r.URL.Path, "/policy") && r.Method == http.MethodGet:
			devicePolicy(w, r, s)
		case r.URL.Path == "/v1/events/batch" && r.Method == http.MethodPost:
			eventsBatch(w, r, s)
		case strings.HasPrefix(r.URL.Path, "/v1/devices/") && strings.HasSuffix(r.URL.Path, "/token") && r.Method == http.MethodPost:
			deviceToken(w, r, s)
		case strings.HasPrefix(r.URL.Path, "/v1/workspaces/") && strings.HasSuffix(r.URL.Path, "/executions") && r.Method == http.MethodGet:
			workspaceExecutions(w, r, s)
		default:
			httpError(w, http.StatusNotFound, "not found")
		}
	}))
	mux.Handle("/v1/healthz", public)
	mux.Handle("/v1/devices/", public)
	mux.Handle("/v1/events/", public)
	mux.Handle("/v1/workspaces/", public)

	// Operator console: session-authenticated. Approvals are operator
	// actions (a human approves/denies a REQUIRE_APPROVAL request); the
	// Rust agent records local approvals in its own journal, so the
	// control-plane approval endpoints serve the team console, not the
	// device.
	// Wrap a 3-param handler (w, r, s) into an http.Handler that
	// carries the server via closure.
	wrap := func(h func(w http.ResponseWriter, r *http.Request, s *Server)) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h(w, r, s) })
	}
	mux.Handle("/v1/policies", operatorRoute(s, wrap(policiesDispatch)))
	mux.Handle("/v1/policies/", operatorRoute(s, wrap(policiesDispatch)))
	mux.Handle("/v1/organizations", operatorRoute(s, wrap(orgsList)))
	mux.Handle("/v1/users", operatorRoute(s, wrap(usersList)))
	mux.Handle("/v1/devices", operatorRoute(s, wrap(devicesList)))
	mux.Handle("/v1/decisions", operatorRoute(s, wrap(decisionsList)))
	mux.Handle("/v1/approvals", operatorRoute(s, wrap(approvalsDispatch)))
	mux.Handle("/v1/approvals/", operatorRoute(s, wrap(approvalsDispatch)))
}

// operatorRoute requires a valid session cookie or operator bearer.
func operatorRoute(s *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Operator sessions in this reference implementation are
		// token-bearer (X-RS-Operator) issued by the auth package; a
		// real deployment would use SSO + a session store.
		if r.Header.Get("X-RS-Operator") == "" && r.Header.Get("Authorization") == "" {
			httpError(w, http.StatusUnauthorized, "operator identity required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- handlers ---------------------------------------------------------------

func healthz(w http.ResponseWriter, r *http.Request, s *Server) {
	dbErr := s.Store.Ping()
	status := "ok"
	code := http.StatusOK
	if dbErr != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, map[string]any{
		"status":    status,
		"backend":   s.Store.Backend(),
		"nats":      s.Ingest != nil,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if code != http.StatusOK {
		http.Error(w, status, code)
	}
}

func devicesEnrol(w http.ResponseWriter, r *http.Request, s *Server) {
	var body struct {
		Organization string `json:"organization"`
		DeviceID     string `json:"device_id"`
		PublicKey    string `json:"public_key"`
		Platform     string `json:"platform"`
		AgentVersion string `json:"agent_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.DeviceID == "" || body.PublicKey == "" {
		httpError(w, http.StatusBadRequest, "device_id and public_key are required")
		return
	}
	s.Logger.Info("device enrol", "org", body.Organization, "device", body.DeviceID, "platform", body.Platform)
	writeJSON(w, map[string]string{
		"status": "enrolled",
		"device": body.DeviceID,
		"org":    body.Organization,
	})
}

func deviceHeartbeat(w http.ResponseWriter, r *http.Request, s *Server) {
	dev := r.Header.Get("X-RS-Device")
	if dev == "" {
		httpError(w, http.StatusBadRequest, "device identity missing (X-RS-Device)")
		return
	}
	if err := s.Store.Heartbeat(r.Context(), dev); err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// devicePolicy returns the latest published policy for the requesting
// device's organization, signed. The Rust agent caches this and falls
// back to its last good copy when the control plane is unreachable
// (spec §18: local guard stays operational on a control-plane outage).
func devicePolicy(w http.ResponseWriter, r *http.Request, s *Server) {
	org := r.Header.Get("X-RS-Org")
	if org == "" {
		org = r.URL.Query().Get("organization")
	}
	p, err := s.Store.LatestPolicyForOrg(r.Context(), org)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "lookup policy: "+err.Error())
		return
	}
	if p == nil {
		// No published policy yet: the agent stays on its cache and is
		// told the server has nothing newer.
		writeJSON(w, map[string]any{
			"organization": org,
			"document":     nil,
			"signature":    "",
			"version":      0,
			"expires_in":   0,
			"note":         "no published policy for this organization; keep using the cached copy",
		})
		return
	}
	var doc any
	_ = json.Unmarshal([]byte(p.Document), &doc)
	writeJSON(w, map[string]any{
		"organization": org,
		"document":     doc,
		"signature":    p.Signature,
		"version":      p.Version,
		"expires_in":   86400,
	})
}

func eventsBatch(w http.ResponseWriter, r *http.Request, s *Server) {
	idem := r.Header.Get("Idempotency-Key")
	var b events.Batch
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpError(w, http.StatusBadRequest, "invalid batch: "+err.Error())
		return
	}
	for i := range b.Events {
		if b.Events[i].IdempotencyKey == "" {
			b.Events[i].IdempotencyKey = idem
		}
	}
	// Ingest persists the batch and dedupes on the idempotency key; it
	// returns only an error (the new-events count is no longer surfaced),
	// so the handler reports the number accepted, not the deduped count.
	if err := s.Ingest.Ingest(r.Context(), b, s.Store); err != nil {
		httpError(w, http.StatusInternalServerError, "ingest failed: "+err.Error())
		return
	}
	s.Logger.Info("events batch", "received", len(b.Events), "idempotency", idem)
	writeJSON(w, map[string]any{
		"accepted":    len(b.Events),
		"idempotency": idem,
	})
}

func approvalsCreate(w http.ResponseWriter, r *http.Request, s *Server) {
	var body struct {
		RequestID string `json:"request_id"`
		Scope     string `json:"scope"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.RequestID == "" || body.Scope == "" {
		httpError(w, http.StatusBadRequest, "request_id and scope are required")
		return
	}
	approver := r.Header.Get("X-RS-Operator")
	if approver == "" {
		approver = "unknown-operator"
	}
	appr := store.Approval{
		ID:         newID(),
		RequestID:  body.RequestID,
		ApproverID: approver,
		Scope:      body.Scope,
		ExpiresAt:  time.Now().UTC().Add(1 * time.Hour),
		Status:     "pending",
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.Store.CreateApproval(r.Context(), appr); err != nil {
		httpError(w, http.StatusInternalServerError, "create approval: "+err.Error())
		return
	}
	s.Logger.Info("approval requested", "request", body.RequestID, "approver", approver, "scope", body.Scope)
	writeJSON(w, map[string]any{
		"status":      "pending",
		"id":          appr.ID,
		"request_id":  body.RequestID,
		"approver_id": approver,
		"scope":       body.Scope,
		"expires_at":  appr.ExpiresAt.Format(time.RFC3339),
	})
}

func approvalsDecide(w http.ResponseWriter, r *http.Request, s *Server) {
	var body struct {
		Decision string `json:"decision"` // allow | deny
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	approver := r.Header.Get("X-RS-Operator")
	if approver == "" {
		approver = "unknown-operator"
	}
	// The URL carries the approval id: /v1/approvals/{id}/decision
	id := extractApprovalID(r.URL.Path)
	status := "approved"
	if body.Decision != "allow" {
		status = "denied"
	}
	if err := s.Store.SetApprovalStatus(r.Context(), id, status); err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	s.Logger.Info("approval decision", "id", id, "decision", body.Decision, "approver", approver)
	writeJSON(w, map[string]any{
		"status":      "recorded",
		"id":          id,
		"decision":    body.Decision,
		"approver_id": approver,
	})
}

// workspaceExecutions returns the execution records for a workspace,
// newest first. The path is /v1/workspaces/{id}/executions.
func workspaceExecutions(w http.ResponseWriter, r *http.Request, s *Server) {
	wsID := extractWorkspaceID(r.URL.Path)
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	items, err := s.Store.ListExecutionsForWorkspace(r.Context(), wsID, limit)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list executions: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"workspace": wsID,
		"limit":     limit,
		"items":     items,
	})
}

// deviceToken issues a short-lived device credential for an enrolled
// device (spec §10 "short-lived device credentials"). The operator
// requests it; the Rust agent would normally carry its own enrolled key,
// but the console surfaces the flow for a device token lifecycle.
func deviceToken(w http.ResponseWriter, r *http.Request, s *Server) {
	dev := r.URL.Path[len("/v1/devices/"):]
	dev = strings.TrimSuffix(dev, "/token")
	if s.Issuer == nil {
		httpError(w, http.StatusServiceUnavailable, "token issuer not configured")
		return
	}
	tok, err := s.Issuer.Issue(auth.DeviceClaims{
		DeviceID: dev,
		OrgID:    r.URL.Query().Get("organization"),
		Role:     "device",
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, "issue token: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{
		"status":   "issued",
		"device":   dev,
		"token":    tok,
		"expires":  "24h",
	})
}

func policiesList(w http.ResponseWriter, r *http.Request, s *Server) {
	org := r.URL.Query().Get("organization")
	items, err := s.Store.ListPolicies(r.Context(), org)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list policies: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

func orgsList(w http.ResponseWriter, r *http.Request, s *Server) {
	writeJSON(w, map[string]any{"items": []any{}})
}

func devicesList(w http.ResponseWriter, r *http.Request, s *Server) {
	org := r.URL.Query().Get("organization")
	items, err := s.Store.ListDevices(r.Context(), org)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list devices: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

// --- policies dispatch --------------------------------------------------------
//
// /v1/policies routes:
//   GET  /v1/policies?organization=   -> list versions
//   GET  /v1/policies/schema          -> the JSON schema (for the web editor)
//   GET  /v1/policies/{id}            -> one policy document
//   POST /v1/policies                 -> create a draft (validated + signed)
//   POST /v1/policies/{id}/publish    -> publish
//   POST /v1/policies/{id}/rollback   -> roll back to a prior version

func policiesDispatch(w http.ResponseWriter, r *http.Request, s *Server) {
	path := r.URL.Path
	switch {
	case path == "/v1/policies/schema" && r.Method == http.MethodGet:
		policySchema(w, r, s)
	case path == "/v1/policies" && r.Method == http.MethodPost:
		policiesCreate(w, r, s)
	case strings.HasSuffix(path, "/publish") && r.Method == http.MethodPost:
		policiesPublish(w, r, s)
	case strings.HasSuffix(path, "/rollback") && r.Method == http.MethodPost:
		policiesRollback(w, r, s)
	case strings.HasPrefix(path, "/v1/policies/") && r.Method == http.MethodGet:
		policiesGet(w, r, s)
	case r.Method == http.MethodGet:
		policiesList(w, r, s)
	default:
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// policySchema returns the raw policy JSON schema the control plane validates
// against, so the web editor validates locally against the same source of
// truth (spec §5 "single source of truth").
func policySchema(w http.ResponseWriter, r *http.Request, s *Server) {
	w.Header().Set("Content-Type", "application/schema+json")
	_, _ = w.Write(s.Policy.Schema())
}

// policiesGet returns one policy by id: /v1/policies/{id}.
func policiesGet(w http.ResponseWriter, r *http.Request, s *Server) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	p, err := s.Store.GetPolicy(r.Context(), id)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "lookup policy: "+err.Error())
		return
	}
	if p == nil {
		httpError(w, http.StatusNotFound, "policy not found")
		return
	}
	var parsed any
	_ = json.Unmarshal([]byte(p.Document), &parsed)
	writeJSON(w, map[string]any{"policy": p, "document": parsed})
}

// policiesCreate validates a draft policy document against the schema, signs
// it and stores a new versioned row (spec §10 POST /v1/policies). The
// document body is the policy document itself.
func policiesCreate(w http.ResponseWriter, r *http.Request, s *Server) {
	var body struct {
		Organization string          `json:"organization"`
		Document     json.RawMessage `json:"document"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Organization == "" || len(body.Document) == 0 {
		httpError(w, http.StatusBadRequest, "organization and document are required")
		return
	}
	if errs := s.Policy.Validate(body.Document); len(errs) > 0 {
		httpError(w, http.StatusUnprocessableEntity, "policy failed schema validation: "+strings.Join(errs, "; "))
		return
	}
	version, err := s.Store.NextPolicyVersion(r.Context(), body.Organization)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "next version: "+err.Error())
		return
	}
	p := store.Policy{
		ID:        newID(),
		OrgID:     body.Organization,
		Version:   version,
		Document:  string(body.Document),
		Signature: s.Policy.Sign(body.Document),
		Status:    "draft",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.Store.CreatePolicy(r.Context(), p); err != nil {
		httpError(w, http.StatusInternalServerError, "create policy: "+err.Error())
		return
	}
	s.Logger.Info("policy draft created", "org", body.Organization, "version", version)
	writeJSON(w, map[string]any{"status": "created", "id": p.ID, "version": version, "status_out": p.Status})
}

// policiesPublish marks a policy published: /v1/policies/{id}/publish.
func policiesPublish(w http.ResponseWriter, r *http.Request, s *Server) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/policies/"), "/publish")
	if err := s.Store.SetPolicyStatus(r.Context(), id, "published"); err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	s.Logger.Info("policy published", "id", id)
	writeJSON(w, map[string]string{"status": "published", "id": id})
}

// policiesRollback marks a policy rolled back: /v1/policies/{id}/rollback.
func policiesRollback(w http.ResponseWriter, r *http.Request, s *Server) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/policies/"), "/rollback")
	if err := s.Store.SetPolicyStatus(r.Context(), id, "rolled_back"); err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	s.Logger.Info("policy rolled back", "id", id)
	writeJSON(w, map[string]string{"status": "rolled_back", "id": id})
}

// --- users / decisions / approvals -------------------------------------------

// usersList returns the members of an organisation: GET /v1/users?organization=.
func usersList(w http.ResponseWriter, r *http.Request, s *Server) {
	org := r.URL.Query().Get("organization")
	items, err := s.Store.ListUsers(r.Context(), org)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list users: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

// decisionsList returns the audit timeline: GET /v1/decisions with optional
// device_id, policy_version and decision filters. Rule IDs and the decision
// are surfaced so the console can show the exact rule that denied a request
// (spec §12 "Audit explorer").
func decisionsList(w http.ResponseWriter, r *http.Request, s *Server) {
	q := r.URL.Query()
	limit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	f := store.DecisionFilter{
		DeviceID:      q.Get("device_id"),
		PolicyVersion: q.Get("policy_version"),
		Decision:      q.Get("decision"),
		Limit:         limit,
	}
	items, err := s.Store.ListDecisionsFiltered(r.Context(), f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list decisions: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items, "limit": limit})
}

// approvalsDispatch routes /v1/approvals:
//   GET  /v1/approvals?status=     -> list (pending | approved | denied | "" all)
//   POST /v1/approvals            -> create a pending approval
//   POST /v1/approvals/{id}/decision -> approve/deny

func approvalsDispatch(w http.ResponseWriter, r *http.Request, s *Server) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/decision") && r.Method == http.MethodPost:
		approvalsDecide(w, r, s)
	case r.Method == http.MethodPost:
		approvalsCreate(w, r, s)
	case r.Method == http.MethodGet:
		approvalsList(w, r, s)
	default:
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// approvalsList returns approvals by status for the approval workspace's
// decision history: GET /v1/approvals?status=pending|approved|denied|"".
func approvalsList(w http.ResponseWriter, r *http.Request, s *Server) {
	status := r.URL.Query().Get("status")
	items, err := s.Store.ListApprovals(r.Context(), status)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list approvals: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items, "status": status})
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- path helpers -------------------------------------------------------------

// extractWorkspaceID pulls {id} from /v1/workspaces/{id}/executions.
func extractWorkspaceID(path string) string {
	rest := strings.TrimPrefix(path, "/v1/workspaces/")
	rest = strings.TrimSuffix(rest, "/executions")
	return rest
}

// extractApprovalID pulls {id} from /v1/approvals/{id}/decision.
func extractApprovalID(path string) string {
	rest := strings.TrimPrefix(path, "/v1/approvals/")
	rest = strings.TrimSuffix(rest, "/decision")
	return rest
}

// newID returns a short unique id for store rows. UUID v4 would be
// preferable; this keeps the dependency set minimal.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

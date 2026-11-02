// Package api wires the HTTP control plane: device enrolment, policy
// distribution, event ingestion, approvals and the operator console's
// read endpoints.
//
// Every handler returns structured JSON through a single error envelope
// ({"error":{"code","message"}}). Authorization is real, not a
// presence-check:
//
//   - Operator routes verify a short-lived operator token (HMAC, same
//     scheme as device tokens, spec §10/§11) in keyed mode.
//   - Device routes verify a short-lived DEVICE token issued by
//     /v1/devices/{id}/token, EXCEPT the very first enrol, which is the
//     bootstrapping exception (documented in docs/API.md; spec §6
//     trust boundary: a compromised agent cannot forge a trusted audit
//     identity because /v1/events/batch requires a valid device token).
//
// Dev mode (no RUNSHIELD_OPERATOR_KEY configured) preserves the open
// zero-config behaviour: requests pass through, a WARN is logged per
// unauthenticated request, and every response carries X-RS-Dev-Mode: true.
// When the key IS set, open mode is off and 401/403 use the shared
// error envelope.
//
// No handler touches a policy decision: the security-critical path lives
// entirely in the Rust agent (spec §5 "important architecture decision").
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

// --- stable error codes (the single envelope, spec §10) ---------------------

const (
	ErrUnauthorized    = "err_unauthorized"
	ErrForbidden       = "err_forbidden"
	ErrRateLimited     = "err_rate_limited"
	ErrInvalidRequest  = "err_invalid_request"
	ErrPayloadTooLarge = "err_payload_too_large"
	ErrNotFound        = "err_not_found"
	ErrConflict        = "err_conflict"
	ErrInternal        = "err_internal"
)

// Body size caps. events/batch is capped on both rows and bytes; other
// POST bodies on bytes only (documented in docs/SCALING.md).
const (
	maxBatchBytes    = 1 << 20 // 1 MiB, /v1/events/batch
	maxBatchRows     = 500
	maxPolicyBytes   = 1 << 20 // 1 MiB, POST /v1/policies
	maxSmallBodyByte = 16 << 10 // 16 KiB, small JSON bodies
)

// Rate class names (shared with config; defaults in config.RateClassDefaults).
const (
	classEvents    = "events"
	classEnrol     = "enrol"
	classHeartbeat = "heartbeat"
	classDevice    = "device"
	classOperator  = "operator"
)

// Server bundles all dependencies for the HTTP handlers.
type Server struct {
	Store       store.Store
	Policy      *policy.Service
	Ingest      *events.Ingestor
	Issuer      *auth.TokenIssuer
	Operators   *auth.OperatorVerifier // keyed-mode operator verification
	Devices     *auth.DeviceVerifier   // keyed-mode device verification
	Limiters    map[string]*ratelimit.Limiter
	CORSOrigins []string // empty = dev mode (CORS `*`)
	DevMode     bool
	Logger      *slog.Logger
}

// NewServerDeps groups every dependency so NewServer stays readable.
type NewServerDeps struct {
	Store       store.Store
	Policy      *policy.Service
	Ingest      *events.Ingestor
	Issuer      *auth.TokenIssuer
	Operators   *auth.OperatorVerifier
	Devices     *auth.DeviceVerifier
	Limiters    map[string]*ratelimit.Limiter
	CORSOrigins []string
	DevMode     bool
	Logger      *slog.Logger
}

// NewServer builds a Server.
func NewServer(d NewServerDeps) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Limiters == nil {
		d.Limiters = map[string]*ratelimit.Limiter{}
	}
	return &Server{
		Store: d.Store, Policy: d.Policy, Ingest: d.Ingest, Issuer: d.Issuer,
		Operators: d.Operators, Devices: d.Devices, Limiters: d.Limiters,
		CORSOrigins: d.CORSOrigins, DevMode: d.DevMode, Logger: d.Logger,
	}
}

// handleFunc is a handler that already has server access bound.
type handleFunc func(w http.ResponseWriter, r *http.Request)

// Routes registers all control-plane endpoints on mux. A single catch-all
// is registered so every response passes through the hardening wrapper
// (security headers, CORS, dev-mode marker, 404 envelope).
func (s *Server) Routes(mux *http.ServeMux) {
	inner := http.NewServeMux()

	// Public / device-facing, rate-limited per class.
	inner.HandleFunc("/v1/healthz", s.limit(classDevice, s.handleHealthz))
	inner.HandleFunc("/v1/ready", s.handleReady) // probes: not rate-limited
	inner.HandleFunc("/v1/devices/enrol", s.device(classEnrol, true, s.handleDevicesEnrol))
	inner.HandleFunc("/v1/devices/", s.deviceDispatch)
	inner.HandleFunc("/v1/events/", s.device(classEvents, false, s.handleEventsBatch))
	inner.HandleFunc("/v1/workspaces/", s.device(classDevice, false, s.handleWorkspaceExecutions))

	// Operator console: policies, orgs, users, devices, decisions, approvals.
	op := func(h handleFunc) http.HandlerFunc {
		return http.HandlerFunc(s.limit(classOperator, s.operatorRoute(h)))
	}
	inner.HandleFunc("/v1/policies", op(s.handlePoliciesDispatch))
	inner.HandleFunc("/v1/policies/", op(s.handlePoliciesDispatch))
	inner.HandleFunc("/v1/organizations", op(s.handleOrgsList))
	inner.HandleFunc("/v1/users", op(s.handleUsersList))
	inner.HandleFunc("/v1/devices", op(s.handleDevicesList))
	inner.HandleFunc("/v1/decisions", op(s.handleDecisionsList))
	inner.HandleFunc("/v1/approvals", op(s.handleApprovalsDispatch))
	inner.HandleFunc("/v1/approvals/", op(s.handleApprovalsDispatch))

	// Catch-all: any path the patterns above didn't match returns the
	// 404 error envelope (the default mux 404 would be plain text).
	inner.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, ErrNotFound, "not found")
	})

	mux.Handle("/", s.harden(inner))
}

// --- middleware --------------------------------------------------------------

// limit enforces the named rate class before auth so an over-budget
// caller is rejected cheaply. The bucket is consumed on entry.
func (s *Server) limit(class string, next handleFunc) handleFunc {
	l := s.Limiters[class]
	if l == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if !l.Allow(key) {
			w.Header().Set("Retry-After", strconv.Itoa(l.RetryAfterSeconds(key)))
			writeError(w, http.StatusTooManyRequests, ErrRateLimited, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

// device enforces a DEVICE token (keyed mode) and applies the rate class.
// exception=true marks the bootstrapping enrol (no prior credential).
func (s *Server) device(class string, exception bool, next handleFunc) handleFunc {
	var authNext handleFunc
	if !exception && s.keyed() {
		// Keyed mode: a valid device token is required.
		authNext = func(w http.ResponseWriter, r *http.Request) {
			claims, ok := s.DeviceClaims(w, r)
			if !ok {
				return
			}
			r.Header.Set("X-RS-Device", claims.DeviceID)
			r.Header.Set("X-RS-Org", claims.OrgID)
			next(w, r)
		}
	} else {
		// Dev mode (open, WARN-logged) or the enrol bootstrap exception
		// (keyed mode, silent: the device has no credential yet).
		authNext = func(w http.ResponseWriter, r *http.Request) {
			if !s.keyed() {
				s.Logger.Warn("dev-mode unauthenticated device request", "path", r.URL.Path)
			}
			next(w, r)
		}
	}
	return s.limit(class, authNext)
}

// operatorRoute enforces a real operator token in keyed mode; open +
// WARN-logged in dev mode (preserves today's zero-config behaviour).
func (s *Server) operatorRoute(next handleFunc) handleFunc {
	if !s.keyed() {
		return func(w http.ResponseWriter, r *http.Request) {
			s.Logger.Warn("dev-mode unauthenticated operator request", "path", r.URL.Path)
			next(w, r)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Operators == nil {
			writeError(w, http.StatusUnauthorized, ErrUnauthorized, "operator verification not configured")
			return
		}
		tok := stripBearer(r.Header.Get("Authorization"))
		if tok == "" {
			tok = r.Header.Get("X-RS-Operator")
		}
		claims, ok := s.Operators.Verify(tok)
		if !ok {
			writeError(w, http.StatusUnauthorized, ErrUnauthorized, "invalid or expired operator token")
			return
		}
		// Forward the verified identity; handlers read X-RS-Operator.
		r.Header.Set("X-RS-Operator", claims.DeviceID)
		next(w, r)
	}
}

// keyed reports whether real token verification is configured.
func (s *Server) keyed() bool { return !s.DevMode }

// DeviceClaims verifies the bearer device token, writing a 401 on failure.
func (s *Server) DeviceClaims(w http.ResponseWriter, r *http.Request) (*auth.DeviceClaims, bool) {
	if s.Devices == nil {
		writeError(w, http.StatusUnauthorized, ErrUnauthorized, "device token verification not configured")
		return nil, false
	}
	claims, ok := s.Devices.Verify(stripBearer(r.Header.Get("Authorization")))
	if !ok {
		writeError(w, http.StatusUnauthorized, ErrUnauthorized, "invalid or expired device token")
		return nil, false
	}
	return claims, true
}

// deviceDispatch routes the /v1/devices/ subtree (heartbeat/policy/token).
func (s *Server) deviceDispatch(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/heartbeat") && r.Method == http.MethodPost:
		h := s.device(classHeartbeat, false, s.handleDeviceHeartbeat)
		h(w, r)
	case strings.HasSuffix(p, "/policy") && r.Method == http.MethodGet:
		h := s.device(classDevice, false, s.handleDevicePolicy)
		h(w, r)
	case strings.HasSuffix(p, "/token") && r.Method == http.MethodPost:
		// Token minting is an operator action (a device token does not
		// mint its own successor); it lives on the public path so the
		// agent can request it, but requires the operator identity in
		// keyed mode.
		h := s.limit(classDevice, s.operatorRoute(s.handleDeviceToken))
		h(w, r)
	default:
		writeError(w, http.StatusNotFound, ErrNotFound, "not found")
	}
}

// --- probes ------------------------------------------------------------------

// handleHealthz: liveness/alias, kept EXACTLY as before the hardening —
// the web topbar and the compose smoke test depend on this shape.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	dbErr := s.Store.Ping()
	status := "ok"
	if dbErr != nil {
		status = "degraded"
	}
	writeJSON(w, map[string]any{
		"status":    status,
		"backend":   s.Store.Backend(),
		"nats":      s.Ingest != nil,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleReady is the readiness probe: 503 until the store answers, 200
// after. It is a gate, not an alias: unlike healthz it fails closed.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Ping(); err != nil {
		writeError(w, http.StatusServiceUnavailable, ErrInternal, "store not ready: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ready", "backend": s.Store.Backend()})
}

// --- device handlers ---------------------------------------------------------

// handleDevicesEnrol is the bootstrapping exception: the first enrol
// needs no prior credential (documented in docs/API.md).
func (s *Server) handleDevicesEnrol(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, ErrNotFound, "not found")
		return
	}
	var body struct {
		Organization string `json:"organization"`
		DeviceID     string `json:"device_id"`
		PublicKey    string `json:"public_key"`
		Platform     string `json:"platform"`
		AgentVersion string `json:"agent_version"`
	}
	if err := readCappedJSON(w, r, maxSmallBodyByte, &body); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.DeviceID == "" || body.PublicKey == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "device_id and public_key are required")
		return
	}
	s.Logger.Info("device enrol", "org", body.Organization, "device", body.DeviceID, "platform", body.Platform)
	writeJSON(w, map[string]string{
		"status": "enrolled",
		"device": body.DeviceID,
		"org":    body.Organization,
	})
}

func (s *Server) handleDeviceHeartbeat(w http.ResponseWriter, r *http.Request) {
	dev := r.Header.Get("X-RS-Device")
	if dev == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "device identity missing (X-RS-Device)")
		return
	}
	if err := s.Store.Heartbeat(r.Context(), dev); err != nil {
		writeError(w, http.StatusNotFound, ErrNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// handleDevicePolicy returns the latest published policy for the
// requesting device's organization, signed.
func (s *Server) handleDevicePolicy(w http.ResponseWriter, r *http.Request) {
	org := r.Header.Get("X-RS-Org")
	if org == "" {
		org = r.URL.Query().Get("organization")
	}
	if org == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "organization scope required")
		return
	}
	p, err := s.Store.LatestPolicyForOrg(r.Context(), org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "lookup policy: "+err.Error())
		return
	}
	if p == nil {
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

// handleEventsBatch ingests an agent audit batch. The device-token
// check on this route is what enforces the spec §6 trust boundary: a
// compromised agent cannot forge a trusted audit identity because every
// batch must carry a valid, short-lived device credential.
func (s *Server) handleEventsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, ErrNotFound, "not found")
		return
	}
	idem := r.Header.Get("Idempotency-Key")
	var b events.Batch
	if err := readCappedJSON(w, r, maxBatchBytes, &b); err != nil {
		if isPayloadOverflow(err) {
			writeError(w, http.StatusRequestEntityTooLarge, ErrPayloadTooLarge, "batch exceeds byte cap")
			return
		}
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid batch: "+err.Error())
		return
	}
	if len(b.Events) > maxBatchRows {
		writeError(w, http.StatusRequestEntityTooLarge, ErrPayloadTooLarge,
			"batch exceeds "+strconv.Itoa(maxBatchRows)+" row cap")
		return
	}
	for i := range b.Events {
		if b.Events[i].IdempotencyKey == "" {
			b.Events[i].IdempotencyKey = idem
		}
	}
	if err := s.Ingest.Ingest(r.Context(), b, s.Store); err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "ingest failed: "+err.Error())
		return
	}
	s.Logger.Info("events batch", "received", len(b.Events), "idempotency", idem)
	writeJSON(w, map[string]any{
		"accepted":    len(b.Events),
		"idempotency": idem,
	})
}

func (s *Server) handleWorkspaceExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, ErrNotFound, "not found")
		return
	}
	wsID := extractWorkspaceID(r.URL.Path)
	if wsID == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "workspace id required")
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	items, err := s.Store.ListExecutionsForWorkspace(r.Context(), wsID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "list executions: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"workspace": wsID,
		"limit":     limit,
		"items":     items,
	})
}

// handleDeviceToken mints a short-lived device credential (spec §10
// "short-lived device credentials"). Operator-gated in keyed mode.
func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, ErrNotFound, "not found")
		return
	}
	dev := extractDeviceID(r.URL.Path)
	if dev == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "device id required")
		return
	}
	if s.Issuer == nil {
		writeError(w, http.StatusServiceUnavailable, ErrInternal, "token issuer not configured")
		return
	}
	tok, err := s.Issuer.Issue(auth.DeviceClaims{
		DeviceID: dev,
		OrgID:    r.URL.Query().Get("organization"),
		Role:     "device",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "issue token: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{
		"status":  "issued",
		"device":  dev,
		"token":   tok,
		"expires": "24h",
	})
}

// --- policies ----------------------------------------------------------------

func (s *Server) handlePoliciesDispatch(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/v1/policies/schema" && r.Method == http.MethodGet:
		s.handlePolicySchema(w, r)
	case path == "/v1/policies" && r.Method == http.MethodPost:
		s.handlePoliciesCreate(w, r)
	case strings.HasSuffix(path, "/publish") && r.Method == http.MethodPost:
		s.handlePoliciesPublish(w, r)
	case strings.HasSuffix(path, "/rollback") && r.Method == http.MethodPost:
		s.handlePoliciesRollback(w, r)
	case strings.HasPrefix(path, "/v1/policies/") && r.Method == http.MethodGet:
		s.handlePoliciesGet(w, r)
	case r.Method == http.MethodGet:
		s.handlePoliciesList(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

// handlePolicySchema returns the raw policy JSON schema the control plane
// validates against, so the web editor validates locally against the same
// source of truth (spec §5 "single source of truth").
func (s *Server) handlePolicySchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/schema+json")
	_, _ = w.Write(s.Policy.Schema())
}

func (s *Server) handlePoliciesGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	if id == "" || id == "schema" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "policy id required")
		return
	}
	p, err := s.Store.GetPolicy(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "lookup policy: "+err.Error())
		return
	}
	if p == nil {
		writeError(w, http.StatusNotFound, ErrNotFound, "policy not found")
		return
	}
	var parsed any
	_ = json.Unmarshal([]byte(p.Document), &parsed)
	writeJSON(w, map[string]any{"policy": p, "document": parsed})
}

// handlePoliciesCreate validates a draft policy document against the
// schema, signs it and stores a new versioned row. The document byte cap
// is documented in docs/SCALING.md.
func (s *Server) handlePoliciesCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Organization string          `json:"organization"`
		Document     json.RawMessage `json:"document"`
	}
	if err := readCappedJSON(w, r, maxPolicyBytes, &body); err != nil {
		if isPayloadOverflow(err) {
			writeError(w, http.StatusRequestEntityTooLarge, ErrPayloadTooLarge, "policy document exceeds byte cap")
			return
		}
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Organization == "" || len(body.Document) == 0 {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "organization and document are required")
		return
	}
	if errs := s.Policy.Validate(body.Document); len(errs) > 0 {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "policy failed schema validation: "+strings.Join(errs, "; "))
		return
	}
	version, err := s.Store.NextPolicyVersion(r.Context(), body.Organization)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "next version: "+err.Error())
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
		writeError(w, http.StatusInternalServerError, ErrInternal, "create policy: "+err.Error())
		return
	}
	s.Logger.Info("policy draft created", "org", body.Organization, "version", version)
	writeJSON(w, map[string]any{"status": "created", "id": p.ID, "version": version, "status_out": p.Status})
}

func (s *Server) handlePoliciesPublish(w http.ResponseWriter, r *http.Request) {
	id := policyActionID(r.URL.Path, "/publish")
	if id == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "policy id required")
		return
	}
	if err := s.Store.SetPolicyStatus(r.Context(), id, "published"); err != nil {
		writeError(w, http.StatusNotFound, ErrNotFound, err.Error())
		return
	}
	s.Logger.Info("policy published", "id", id)
	writeJSON(w, map[string]string{"status": "published", "id": id})
}

func (s *Server) handlePoliciesRollback(w http.ResponseWriter, r *http.Request) {
	id := policyActionID(r.URL.Path, "/rollback")
	if id == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "policy id required")
		return
	}
	if err := s.Store.SetPolicyStatus(r.Context(), id, "rolled_back"); err != nil {
		writeError(w, http.StatusNotFound, ErrNotFound, err.Error())
		return
	}
	s.Logger.Info("policy rolled back", "id", id)
	writeJSON(w, map[string]string{"status": "rolled_back", "id": id})
}

func (s *Server) handlePoliciesList(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("organization")
	items, err := s.Store.ListPolicies(r.Context(), org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "list policies: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

// --- operator read handlers --------------------------------------------------

func (s *Server) handleOrgsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"items": []any{}})
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("organization")
	items, err := s.Store.ListUsers(r.Context(), org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "list users: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

func (s *Server) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("organization")
	items, err := s.Store.ListDevices(r.Context(), org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "list devices: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items})
}

// handleDecisionsList returns the audit timeline with optional filters.
func (s *Server) handleDecisionsList(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusInternalServerError, ErrInternal, "list decisions: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items, "limit": limit})
}

// --- approvals ---------------------------------------------------------------

func (s *Server) handleApprovalsDispatch(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/decision") && r.Method == http.MethodPost:
		s.handleApprovalsDecide(w, r)
	case r.Method == http.MethodPost:
		s.handleApprovalsCreate(w, r)
	case r.Method == http.MethodGet:
		s.handleApprovalsList(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, ErrInvalidRequest, "method not allowed")
	}
}

func (s *Server) handleApprovalsCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RequestID string `json:"request_id"`
		Scope     string `json:"scope"`
		Reason    string `json:"reason"`
	}
	if err := readCappedJSON(w, r, maxSmallBodyByte, &body); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.RequestID == "" || body.Scope == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "request_id and scope are required")
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
		writeError(w, http.StatusInternalServerError, ErrInternal, "create approval: "+err.Error())
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

func (s *Server) handleApprovalsDecide(w http.ResponseWriter, r *http.Request) {
	id := extractApprovalID(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "approval id required")
		return
	}
	var body struct {
		Decision string `json:"decision"` // allow | deny
		Reason   string `json:"reason"`
	}
	if err := readCappedJSON(w, r, maxSmallBodyByte, &body); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest, "invalid JSON: "+err.Error())
		return
	}
	approver := r.Header.Get("X-RS-Operator")
	if approver == "" {
		approver = "unknown-operator"
	}
	status := "approved"
	if body.Decision != "allow" {
		status = "denied"
	}
	if err := s.Store.SetApprovalStatus(r.Context(), id, status); err != nil {
		writeError(w, http.StatusNotFound, ErrNotFound, err.Error())
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

func (s *Server) handleApprovalsList(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	items, err := s.Store.ListApprovals(r.Context(), status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrInternal, "list approvals: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": items, "status": status})
}

// --- hardening wrapper (headers + CORS + dev marker) -------------------------

// harden applies the security-header baseline, CORS and the dev-mode
// marker to every response, including 404s that the inner mux would
// otherwise serve. The API serves only JSON, so the CSP is a strict
// default-deny: nothing the browser renders from these responses may load
// or frame anything.
func (s *Server) harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		if s.DevMode {
			w.Header().Set("X-RS-Dev-Mode", "true")
		}
		s.applyCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// applyCORS keeps `*` only in dev mode; keyed (production) mode is
// config-driven: a request is answered only when its Origin is in the
// allowlist, otherwise no Access-Control-Allow-Origin is set at all.
func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) {
	const allowHeaders = "Authorization, Content-Type, Idempotency-Key, X-RS-Operator, X-RS-Device, X-RS-Org"
	if len(s.CORSOrigins) == 0 && s.DevMode {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		return
	}
	origin := r.Header.Get("Origin")
	for _, o := range s.CORSOrigins {
		if strings.EqualFold(o, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Vary", "Origin")
			return
		}
	}
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits the ONE error envelope: {"error":{"code","message"}}.
// All non-2xx responses use this; codes are the stable Err* constants.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"code": code, "message": message,
	}})
}

// readCappedJSON decodes a request body of at most `max` bytes.
// Overflow surfaces as a *http.MaxBytesError.
func readCappedJSON(w http.ResponseWriter, r *http.Request, max int, dst any) error {
	rd := http.MaxBytesReader(w, r.Body, int64(max))
	defer rd.Close()
	return json.NewDecoder(rd).Decode(dst)
}

func isPayloadOverflow(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*http.MaxBytesError)
	return ok
}

// --- path helpers -------------------------------------------------------------

func extractWorkspaceID(path string) string {
	rest := strings.TrimPrefix(path, "/v1/workspaces/")
	rest = strings.TrimSuffix(rest, "/executions")
	return rest
}

func extractDeviceID(path string) string {
	rest := strings.TrimPrefix(path, "/v1/devices/")
	rest = strings.TrimSuffix(rest, "/token")
	rest = strings.TrimSuffix(rest, "/")
	return rest
}

func extractApprovalID(path string) string {
	rest := strings.TrimPrefix(path, "/v1/approvals/")
	rest = strings.TrimSuffix(rest, "/decision")
	return rest
}

func policyActionID(path, suffix string) string {
	id := strings.TrimPrefix(path, "/v1/policies/")
	id = strings.TrimSuffix(id, suffix)
	return id
}

// stripBearer tolerates both "Bearer <tok>" and a bare token.
func stripBearer(v string) string {
	if len(v) > 7 && v[:7] == "Bearer " {
		return v[7:]
	}
	return v
}

// newID returns a short unique id for store rows.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

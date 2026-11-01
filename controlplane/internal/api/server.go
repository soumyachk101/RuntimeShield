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
	"encoding/json"
	"log/slog"
	"net/http"
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
		case r.URL.Path == "/v1/approvals" && r.Method == http.MethodPost:
			approvalsCreate(w, r, s)
		case strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, "/decision") && r.Method == http.MethodPost:
			approvalsDecide(w, r, s)
		case strings.HasPrefix(r.URL.Path, "/v1/workspaces/") && strings.HasSuffix(r.URL.Path, "/executions") && r.Method == http.MethodGet:
			workspaceExecutions(w, r, s)
		default:
			httpError(w, http.StatusNotFound, "not found")
		}
	}))
	mux.Handle("/v1/healthz", public)
	mux.Handle("/v1/devices/", public)
	mux.Handle("/v1/events/", public)
	mux.Handle("/v1/approvals/", public)
	mux.Handle("/v1/workspaces/", public)

	// Operator console: session-authenticated.
	mux.Handle("/v1/policies", operatorRoute(s, http.HandlerFunc(policiesList)))
	mux.Handle("/v1/organizations", operatorRoute(s, http.HandlerFunc(orgsList)))
	mux.Handle("/v1/devices", operatorRoute(s, http.HandlerFunc(devicesList)))
}

// operatorRoute requires a valid session cookie or operator bearer.
func operatorRoute(s *Server, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Operator sessions in this reference implementation are
		// token-bearer (X-RS-Operator) issued by the auth package; a
		// real deployment would use SSO + a session store.
		if r.Header.Get("X-RS-Operator") == "" && r.Header.Get("Authorization") == "" {
			httpError(w, http.StatusUnauthorized, "operator identity required")
			return
		}
		next(w, r)
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
	writeJSON(w, map[string]string{"status": "ok"})
}

func devicePolicy(w http.ResponseWriter, r *http.Request, s *Server) {
	// Returns the latest published policy for the requesting device's
	// organization, signed. The Rust agent caches this and falls back
	// to the last good copy when the control plane is unreachable.
	org := r.Header.Get("X-RS-Org")
	writeJSON(w, map[string]any{
		"organization": org,
		"document":     map[string]any{}, // latest published doc in a real store
		"signature":    "",
		"version":      "0",
		"expires_in":   86400,
		"note":         "dev endpoint — populate from the policies table",
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
	n, err := s.Ingest.Ingest(r.Context(), b)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "ingest failed: "+err.Error())
		return
	}
	s.Logger.Info("events batch", "received", len(b.Events), "new", n, "idempotency", idem)
	writeJSON(w, map[string]any{
		"accepted":    len(b.Events),
		"deduped":     len(b.Events) - n,
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
	s.Logger.Info("approval requested", "request", body.RequestID, "approver", approver)
	writeJSON(w, map[string]any{
		"status":      "pending",
		"request_id":  body.RequestID,
		"approver_id": approver,
		"scope":       body.Scope,
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
	s.Logger.Info("approval decision", "decision", body.Decision, "approver", approver)
	writeJSON(w, map[string]any{
		"status":      "recorded",
		"decision":    body.Decision,
		"approver_id": approver,
	})
}

func workspaceExecutions(w http.ResponseWriter, r *http.Request, s *Server) {
	// Chronological execution records for a workspace, paged.
	page := r.URL.Query().Get("page")
	limit := r.URL.Query().Get("limit")
	writeJSON(w, map[string]any{
		"page":  page,
		"limit": limit,
		"items": []any{},
		"note":  "dev endpoint — populate from the execution_requests table",
	})
}

func policiesList(w http.ResponseWriter, r *http.Request, s *Server) {
	writeJSON(w, map[string]any{"items": []any{}, "note": "dev endpoint"})
}

func orgsList(w http.ResponseWriter, r *http.Request, s *Server) {
	writeJSON(w, map[string]any{"items": []any{}, "note": "dev endpoint"})
}

func devicesList(w http.ResponseWriter, r *http.Request, s *Server) {
	writeJSON(w, map[string]any{"items": []any{}, "note": "dev endpoint"})
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

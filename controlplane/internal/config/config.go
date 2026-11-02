// Package config loads and validates the control-plane's environment
// configuration. It is the single source of truth for which backend
// (Postgres vs embedded SQLite) and which auth/rate-limit settings are
// active; failing validation at startup is better than failing mid-request.
package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Environment variable names used by the control plane.
const (
	EnvBackend        = "RUNSHIELD_BACKEND" // "postgres" | "sqlite"
	EnvPGDSN          = "RUNSHIELD_PG_DSN"
	EnvSQLitePath     = "RUNSHIELD_SQLITE_PATH"
	EnvHTTPAddr       = "RUNSHIELD_HTTP_ADDR"
	EnvTLSCert        = "RUNSHIELD_TLS_CERT"
	EnvTLSKey         = "RUNSHIELD_TLS_KEY"
	EnvSignKey        = "RUNSHIELD_SIGN_KEY"
	EnvSessionKey     = "RUNSHIELD_SESSION_KEY"
	EnvOperatorKey    = "RUNSHIELD_OPERATOR_KEY"
	EnvRateLimitRPS   = "RUNSHIELD_RATE_LIMIT_RPS"
	EnvRateLimitBurst = "RUNSHIELD_RATE_LIMIT_BURST"
	EnvCORSOrigins    = "RUNSHIELD_CORS_ORIGINS"
	EnvLogLevel       = "RUNSHIELD_LOG_LEVEL"
	EnvNATSURL        = "RUNSHIELD_NATS_URL"
)

// Per-class rate-limit environment variables.
// RUNSHIELD_RATE_<CLASS>_RPS / RUNSHIELD_RATE_<CLASS>_BURST.
const (
	EnvRateEventsRPS      = "RUNSHIELD_RATE_EVENTS_RPS"
	EnvRateEventsBurst    = "RUNSHIELD_RATE_EVENTS_BURST"
	EnvRateEnrolRPS       = "RUNSHIELD_RATE_ENROL_RPS"
	EnvRateEnrolBurst     = "RUNSHIELD_RATE_ENROL_BURST"
	EnvRateHeartbeatRPS   = "RUNSHIELD_RATE_HEARTBEAT_RPS"
	EnvRateHeartbeatBurst = "RUNSHIELD_RATE_HEARTBEAT_BURST"
	EnvRateDeviceRPS      = "RUNSHIELD_RATE_DEVICE_RPS"
	EnvRateDeviceBurst    = "RUNSHIELD_RATE_DEVICE_BURST"
	EnvRateOperatorRPS    = "RUNSHIELD_RATE_OPERATOR_RPS"
	EnvRateOperatorBurst  = "RUNSHIELD_RATE_OPERATOR_BURST"
)

// BackendKind selects the storage backend.
type BackendKind int

const (
	BackendSQLite BackendKind = iota
	BackendPostgres
)

// Config is the resolved, validated configuration.
type Config struct {
	Backend        BackendKind
	PGDSN          string
	SQLitePath     string
	HTTPAddr       string
	TLSCert        string
	TLSKey         string
	SignKey        []byte
	SessionKey     []byte
	OperatorKey    []byte // RUNSHIELD_OPERATOR_KEY; nil = dev-open mode
	CORSOriginsRaw string  // comma-separated; empty = dev mode (`*`)
	RateLimitRPS   int
	RateLimitBurst int
	RateClasses    map[string]ClassRate
	LogLevel       string
	NATSURL        string // optional; empty disables NATS transport
}

// ClassRate holds one named rate-limit class's budget.
type ClassRate struct {
	RPS   int
	Burst int
}

// Rate class names. Per-class overrides: RUNSHIELD_RATE_<CLASS>_RPS /
// RUNSHIELD_RATE_<CLASS>_BURST (e.g. RUNSHIELD_RATE_EVENTS_RPS).
const (
	// events: /v1/events/batch — highest budget.
	ClassEvents = "events"
	// enrol: /v1/devices/enrol — lowest budget.
	ClassEnrol = "enrol"
	// heartbeat: /v1/devices/{id}/heartbeat
	ClassHeartbeat = "heartbeat"
	// device: /v1/devices/{id}/policy and /v1/devices/{id}/token
	ClassDevice = "device"
	// operator: console routes (policies/orgs/users/devices/decisions/approvals)
	ClassOperator = "operator"
)

// RateClassDefaults: the compiled-in budgets (documented in docs/SCALING.md).
var RateClassDefaults = map[string]ClassRate{
	ClassEvents:     {RPS: 50, Burst: 100},
	ClassEnrol:      {RPS: 5, Burst: 10},
	ClassHeartbeat:  {RPS: 10, Burst: 20},
	ClassDevice:     {RPS: 20, Burst: 40},
	ClassOperator:   {RPS: 10, Burst: 20},
}

// FromEnv reads the environment, applying defaults, and returns an error
// describing exactly which variable is missing or invalid.
func FromEnv() (*Config, error) {
	c := &Config{
		HTTPAddr:       ":8080",
		RateLimitRPS:   50,
		RateLimitBurst: 100,
		LogLevel:       "info",
	}

	backend := strings.ToLower(os.Getenv(EnvBackend))
	switch backend {
	case "", "sqlite":
		c.Backend = BackendSQLite
		c.SQLitePath = firstNonEmpty(os.Getenv(EnvSQLitePath), "data/runshield.db")
	case "postgres":
		c.Backend = BackendPostgres
		if dsn := os.Getenv(EnvPGDSN); dsn == "" {
			return nil, fmt.Errorf("%s is required when RUNSHIELD_BACKEND=postgres", EnvPGDSN)
		} else {
			c.PGDSN = dsn
		}
	default:
		return nil, fmt.Errorf("%s=%q is not one of: sqlite, postgres", EnvBackend, backend)
	}

	if v := os.Getenv(EnvHTTPAddr); v != "" {
		c.HTTPAddr = v
	}
	c.TLSCert = os.Getenv(EnvTLSCert)
	c.TLSKey = os.Getenv(EnvTLSKey)
	c.NATSURL = os.Getenv(EnvNATSURL)

	// Signing key: hex. In dev it may be omitted (the engine falls back to
	// unsigned policies). In production it is mandatory.
	if hexKey := os.Getenv(EnvSignKey); hexKey != "" {
		k, err := decodeHex(hexKey)
		if err != nil {
			return nil, fmt.Errorf("%s is not valid hex: %w", EnvSignKey, err)
		}
		c.SignKey = k
	}
	if hexKey := os.Getenv(EnvSessionKey); hexKey != "" {
		k, err := decodeHex(hexKey)
		if err != nil {
			return nil, fmt.Errorf("%s is not valid hex: %w", EnvSessionKey, err)
		}
		c.SessionKey = k
	}
	// Operator signing key. When absent, the API runs in dev-open mode:
	// operator routes accept any non-empty identity header (WARN logged per
	// request). When present, operator tokens are verified for real.
	if hexKey := os.Getenv(EnvOperatorKey); hexKey != "" {
		k, err := decodeHex(hexKey)
		if err != nil {
			return nil, fmt.Errorf("%s is not valid hex: %w", EnvOperatorKey, err)
		}
		c.OperatorKey = k
	}
	c.CORSOriginsRaw = os.Getenv(EnvCORSOrigins)

	if v := os.Getenv(EnvRateLimitRPS); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s must be a positive integer, got %q", EnvRateLimitRPS, v)
		}
		c.RateLimitRPS = n
	}
	if v := os.Getenv(EnvRateLimitBurst); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s must be a positive integer, got %q", EnvRateLimitBurst, v)
		}
		c.RateLimitBurst = n
	}
	if v := os.Getenv(EnvLogLevel); v != "" {
		c.LogLevel = v
	}

	classes, err := rateClassesFromEnv()
	if err != nil {
		return nil, err
	}
	c.RateClasses = classes

	if c.Backend == BackendSQLite && c.SQLitePath == "" {
		return nil, fmt.Errorf("%s must be set for the embedded backend", EnvSQLitePath)
	}

	log.Printf("config: backend=%v http=%s rate=%d/%d log=%s",
		backendOr("sqlite", c.Backend), c.HTTPAddr, c.RateLimitRPS, c.RateLimitBurst, c.LogLevel)
	return c, nil
}

// rateClassesFromEnv resolves every rate class: defaults, overridden by
// RUNSHIELD_RATE_<CLASS>_RPS / RUNSHIELD_RATE_<CLASS>_BURST.
func rateClassesFromEnv() (map[string]ClassRate, error) {
	out := map[string]ClassRate{}
	for name, d := range RateClassDefaults {
		out[name] = d
	}
	envFor := map[string][2]string{
		ClassEvents:    {EnvRateEventsRPS, EnvRateEventsBurst},
		ClassEnrol:     {EnvRateEnrolRPS, EnvRateEnrolBurst},
		ClassHeartbeat: {EnvRateHeartbeatRPS, EnvRateHeartbeatBurst},
		ClassDevice:    {EnvRateDeviceRPS, EnvRateDeviceBurst},
		ClassOperator:  {EnvRateOperatorRPS, EnvRateOperatorBurst},
	}
	for name, envs := range envFor {
		cr := out[name]
		if v := os.Getenv(envs[0]); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%s must be a positive integer, got %q", envs[0], v)
			}
			cr.RPS = n
		}
		if v := os.Getenv(envs[1]); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("%s must be a positive integer, got %q", envs[1], v)
			}
			cr.Burst = n
		}
		out[name] = cr
	}
	return out, nil
}

// RateFor returns the effective budget for a rate class, falling back to
// the compiled-in default when the class is unknown.
func (c *Config) RateFor(class string) ClassRate {
	if c.RateClasses != nil {
		if cr, ok := c.RateClasses[class]; ok {
			return cr
		}
	}
	return RateClassDefaults[class]
}

// AuthEnabled reports whether operator token verification is on. Dev mode
// (zero-config) leaves it off so local development still boots without a
// key; any RUNSHIELD_OPERATOR_KEY value switches it on.
func (c *Config) AuthEnabled() bool {
	return c.OperatorKey != nil
}

// CORSOrigins returns the configured cross-origin allowlist (comma
// separated). Empty = dev mode, where the API answers preflights with
// `Access-Control-Allow-Origin: *`.
func (c *Config) CORSOrigins() []string {
	if c.CORSOriginsRaw == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(c.CORSOriginsRaw, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func backendOr(def string, b BackendKind) string {
	if b == BackendPostgres {
		return "postgres"
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var b byte
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b); err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

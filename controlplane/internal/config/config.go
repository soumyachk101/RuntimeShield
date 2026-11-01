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
	EnvRateLimitRPS   = "RUNSHIELD_RATE_LIMIT_RPS"
	EnvRateLimitBurst = "RUNSHIELD_RATE_LIMIT_BURST"
	EnvLogLevel       = "RUNSHIELD_LOG_LEVEL"
	EnvNATSURL        = "RUNSHIELD_NATS_URL"
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
	RateLimitRPS   int
	RateLimitBurst int
	LogLevel       string
	NATSURL        string // optional; empty disables NATS transport
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

	if c.Backend == BackendSQLite && c.SQLitePath == "" {
		return nil, fmt.Errorf("%s must be set for the embedded backend", EnvSQLitePath)
	}

	log.Printf("config: backend=%v http=%s rate=%d/%d log=%s",
		backendOr("sqlite", c.Backend), c.HTTPAddr, c.RateLimitRPS, c.RateLimitBurst, c.LogLevel)
	return c, nil
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

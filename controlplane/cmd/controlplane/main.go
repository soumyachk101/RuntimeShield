// Command controlplane is the RuntimeShield team control plane.
//
// It is intentionally thin: policy distribution, device/org/user
// management, event ingestion and the console's read API. It never
// evaluates a security decision — that path lives in the Rust agent.
//
// Development mode: RUNSHIELD_BACKEND=sqlite (default) with a local
// data directory. No external service is required. Production:
// RUNSHIELD_BACKEND=postgres with the migrations/ scripts applied.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"runshield.dev/controlplane/internal/api"
	"runshield.dev/controlplane/internal/auth"
	"runshield.dev/controlplane/internal/config"
	"runshield.dev/controlplane/internal/events"
	"runshield.dev/controlplane/internal/policy"
	"runshield.dev/controlplane/internal/ratelimit"
	"runshield.dev/controlplane/internal/store"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		// A misconfiguration must fail fast and loudly.
		slog.Error("configuration invalid", "err", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	backend := "sqlite"
	if cfg.Backend == config.BackendPostgres {
		backend = "postgres"
	}
	st, err := store.NewStore(backend, cfg.PGDSN, cfg.SQLitePath)
	if err != nil {
		logger.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Create tables if missing. The embedded DDL is an idempotent
	// subset; on Postgres the canonical DDL lives in /migrations.
	if err := st.ApplySchema(); err != nil {
		logger.Error("apply schema", "err", err)
		os.Exit(1)
	}

	// Policy service: load the JSON schema from disk. The default path
	// is a sibling of the binary; override with RUNSHIELD_POLICY_SCHEMA.
	schemaPath := os.Getenv("RUNSHIELD_POLICY_SCHEMA")
	if schemaPath == "" {
		schemaPath = "policies/schema/policy.schema.json"
	}
	ps, err := policy.NewService(schemaPath, cfg.SignKey)
	if err != nil {
		logger.Error("init policy service", "err", err)
		os.Exit(1)
	}

	ingest := events.NewIngestor(st.DB(), st.Backend())

	// Token issuer. If no signing key is configured, fall back to a
	// random ephemeral key so the auth path still works in dev, and
	// log that tokens will not survive a restart.
	signKey := cfg.SignKey
	if len(signKey) == 0 {
		signKey = make([]byte, 32)
		if _, err := rand.Read(signKey); err != nil {
			logger.Error("generate ephemeral signing key", "err", err)
			os.Exit(1)
		}
		logger.Warn("no RUNSHIELD_SIGN_KEY set; using an ephemeral key — device tokens will not survive a restart")
	}
	issuer := auth.NewTokenIssuer(signKey, 24*time.Hour)

	rl := ratelimit.New(float64(cfg.RateLimitRPS), cfg.RateLimitBurst)
	server := api.NewServer(st, ps, ingest, issuer, rl, logger)

	mux := http.NewServeMux()
	server.Routes(mux)

	var srv *http.Server
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		srv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			logger.Info("control plane listening (TLS)", "addr", cfg.HTTPAddr)
			if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("serve", "err", err)
			}
		}()
	} else {
		srv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			logger.Info("control plane listening", "addr", cfg.HTTPAddr, "tls", false)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("serve", "err", err)
			}
		}()
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown", "err", err)
	}
	logger.Info("control plane stopped")
}

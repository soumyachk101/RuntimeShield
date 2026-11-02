// Package ratelimit provides per-client token-bucket limiters for the
// control plane. In-memory, single-node; a shared store (Redis) would be
// the natural next step for multi-node deployments.
//
// The control plane uses one named limiter per route class (events,
// enrol, heartbeat, device, operator) rather than a single global bucket,
// so a burst of heartbeats cannot exhaust the budget for event ingestion.
// See docs/SCALING.md for the per-class defaults and env overrides.
package ratelimit

import (
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// bucket is a per-key token bucket.
type bucket struct {
	tokens   float64
	max      float64
	rate     float64 // tokens per second
	lastFill time.Time
}

// Limiter is a per-client token bucket factory + guard.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rps     float64
	burst   int
}

// New returns a limiter allowing `rps` requests/second with `burst`
// tokens of headroom per client key.
func New(rps float64, burst int) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, rps: rps, burst: burst}
}

// For is a named alias for New, used when building the per-class limiters.
func For(rps float64, burst int) *Limiter {
	return New(rps, burst)
}

func (l *Limiter) bucketFor(key string) *bucket {
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(l.burst), max: float64(l.burst), rate: l.rps, lastFill: time.Now()}
		l.buckets[key] = b
	}
	return b
}

// Allow checks and consumes a token for the given key.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketFor(key)
	now := time.Now()
	b.tokens += now.Sub(b.lastFill).Seconds() * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Peek reports whether a token is available WITHOUT consuming one. It
// lets a caller reject a request over budget before doing any work.
func (l *Limiter) Peek(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketFor(key)
	now := time.Now()
	tokens := b.tokens + now.Sub(b.lastFill).Seconds()*b.rate
	if tokens > b.max {
		tokens = b.max
	}
	return tokens >= 1
}

// AllowKey checks and consumes a token for a caller-chosen key (e.g. a
// device id) instead of the remote address.
func (l *Limiter) AllowKey(key string) bool {
	if key == "" {
		key = "anonymous"
	}
	return l.Allow(key)
}

// RetryAfterSeconds estimates the seconds until the key's bucket can serve
// another request; clamped to at least 1.
func (l *Limiter) RetryAfterSeconds(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketFor(key)
	now := time.Now()
	tokens := b.tokens + now.Sub(b.lastFill).Seconds()*b.rate
	if tokens > b.max {
		tokens = b.max
	}
	if tokens >= 1 {
		return 1
	}
	if b.rate <= 0 {
		return 1
	}
	sec := int(math.Ceil((1 - tokens) / b.rate))
	if sec < 1 {
		sec = 1
	}
	return sec
}

// Middleware wraps an http.Handler with per-remote-address limiting.
// A trusted proxy should set X-Forwarded-For; we fall back to
// RemoteAddr so a forged header cannot bypass the limit.
//
// The 429 response carries Retry-After and the shared error envelope.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(r.RemoteAddr) {
			w.Header().Set("Retry-After", strconv.Itoa(l.RetryAfterSeconds(r.RemoteAddr)))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
				"code":    "err_rate_limited",
				"message": "rate limit exceeded",
			}})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Forget drops the bucket for a key (housekeeping for churn).
func (l *Limiter) Forget(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// Package ratelimit provides a per-client token-bucket limiter for
// the public endpoints. In-memory, single-node; a shared store
// (Redis) would be the natural next step for multi-node deployments.
package ratelimit

import (
	"net/http"
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

// Middleware wraps an http.Handler with per-remote-address limiting.
// A trusted proxy should set X-Forwarded-For; we fall back to
// RemoteAddr so a forged header cannot bypass the limit.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(r.RemoteAddr) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
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

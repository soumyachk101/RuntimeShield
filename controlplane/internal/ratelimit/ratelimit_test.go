package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLimiterAllowsBurstThenBlocks(t *testing.T) {
	l := New(0.0001, 2) // ~0 requests/s, burst of 2
	require.True(t, l.Allow("a"), "first within burst")
	require.True(t, l.Allow("a"), "second within burst")
	// Bucket refills negligibly; the third is over the limit.
	require.False(t, l.Allow("a"), "third exceeds burst")
}

func TestLimiterPerKeyIndependence(t *testing.T) {
	l := New(0.0001, 1)
	require.True(t, l.Allow("a"))
	require.False(t, l.Allow("a"))
	require.True(t, l.Allow("b"), "different key has its own bucket")
}

func TestMiddlewareReturns429(t *testing.T) {
	l := New(0.0001, 1)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Prime the bucket with the same remote address the test will use.
	resp1, err := http.Get(srv.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	resp1.Body.Close()

	resp2, err := http.Get(srv.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)
	resp2.Body.Close()
}

package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterPrunesIdleBucketsOnInterval(t *testing.T) {
	limiter := newRateLimiter()
	base := time.Now()

	// One request from a single IP creates one bucket.
	if !limiter.allow("203.0.113.1", "signal", base) {
		t.Fatal("first request should be allowed")
	}
	if got := len(limiter.buckets); got != 1 {
		t.Fatalf("expected 1 bucket, got %d", got)
	}

	// Advance well past the signal cleanup window and the prune interval, then
	// make a request from a different IP. The idle bucket must be swept.
	later := base.Add(25 * time.Minute)
	if !limiter.allow("203.0.113.2", "signal", later) {
		t.Fatal("request from new IP should be allowed")
	}
	if got := len(limiter.buckets); got != 1 {
		t.Fatalf("expected stale bucket pruned leaving 1, got %d", got)
	}
}

func TestRateLimiterDoesNotPruneActiveBucketsBeforeInterval(t *testing.T) {
	limiter := newRateLimiter()
	now := time.Now()

	for i := 0; i < 5; i++ {
		limiter.allow("203.0.113.10", "signal", now.Add(time.Duration(i)*time.Second))
	}
	if got := len(limiter.buckets); got != 1 {
		t.Fatalf("expected 1 active bucket retained, got %d", got)
	}
}

func TestRateLimiterEnforcesBurst(t *testing.T) {
	limiter := newRateLimiter()
	now := time.Now()

	// create burst is 12; the 13th immediate request should be denied.
	var allowed int
	for i := 0; i < 13; i++ {
		if limiter.allow("198.51.100.7", "create", now) {
			allowed++
		}
	}
	if allowed != 12 {
		t.Fatalf("expected exactly 12 allowed within burst, got %d", allowed)
	}
}

func BenchmarkRateLimiterAllow(b *testing.B) {
	limiter := newRateLimiter()
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(time.Millisecond)
		limiter.allow("203.0.113.55", "signal", now)
	}
}

func TestResolveTrustProxyDefaultsTrue(t *testing.T) {
	t.Setenv(envTrustProxy, "")
	if !resolveTrustProxy() {
		t.Fatal("trust proxy should default to true for reverse-proxy deployments")
	}
}

func TestResolveTrustProxyDisable(t *testing.T) {
	for _, v := range []string{"false", "0", "no", "off", "FALSE"} {
		t.Setenv(envTrustProxy, v)
		if resolveTrustProxy() {
			t.Fatalf("trust proxy should be disabled for %q", v)
		}
	}
}

func TestClientIPIgnoresForwardedHeaderWhenProxyUntrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.23")

	if got := clientIP(req, false); got != "203.0.113.9" {
		t.Fatalf("expected RemoteAddr IP when proxy untrusted, got %q", got)
	}
	if got := clientIP(req, true); got != "198.51.100.23" {
		t.Fatalf("expected forwarded IP when proxy trusted, got %q", got)
	}
}

func TestEnsureSameOriginSchemeWithUntrustedProxy(t *testing.T) {
	// Direct exposure: client claims https origin via spoofed header but the
	// connection is plain http. With proxy untrusted, the scheme must not be
	// taken from X-Forwarded-Proto, so the https origin is rejected.
	req := httptest.NewRequest(http.MethodPost, "/ui/rooms/create", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	if err := ensureSameOrigin(req, false); err == nil {
		t.Fatal("expected origin rejection when proxy scheme is untrusted")
	}
	if err := ensureSameOrigin(req, true); err != nil {
		t.Fatalf("expected origin acceptance when proxy trusted, got %v", err)
	}
}

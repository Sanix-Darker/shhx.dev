package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type cspNonceKey struct{}

const (
	maxFormBodyBytes   = 1024
	maxSignalBodyBytes = 64 << 10

	maxDisplayNameLen = 24
	maxRoomCodeLen    = 6
	maxPeerIDLen      = 32

	maxSecretLength     = 4096
	maxPassphraseLength = 128
	maxTOTPCodeLength   = 6
)

var (
	errInvalidRoomCode = errors.New("invalid room code")
	errInvalidPeerID   = errors.New("invalid peer id")
	errInvalidOrigin   = errors.New("invalid origin")
	errRateLimited     = errors.New("rate limit exceeded")
)

type rateConfig struct {
	burst         float64
	refillPerSec  float64
	cleanupWindow time.Duration
}

type rateBucket struct {
	tokens   float64
	lastSeen time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	limits  map[string]rateConfig
	buckets map[string]*rateBucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		limits: map[string]rateConfig{
			"index":   {burst: 60, refillPerSec: 1, cleanupWindow: 15 * time.Minute},
			"preview": {burst: 30, refillPerSec: 0.5, cleanupWindow: 15 * time.Minute},
			"create":  {burst: 12, refillPerSec: 0.2, cleanupWindow: 20 * time.Minute},
			"join":    {burst: 20, refillPerSec: 0.5, cleanupWindow: 20 * time.Minute},
			"events":  {burst: 20, refillPerSec: 0.5, cleanupWindow: 30 * time.Minute},
			"signal":  {burst: 180, refillPerSec: 3, cleanupWindow: 20 * time.Minute},
			"leave":   {burst: 40, refillPerSec: 1, cleanupWindow: 20 * time.Minute},
			"static":  {burst: 120, refillPerSec: 4, cleanupWindow: 15 * time.Minute},
			"other":   {burst: 30, refillPerSec: 0.5, cleanupWindow: 15 * time.Minute},
		},
		buckets: make(map[string]*rateBucket),
	}
}

func (l *rateLimiter) allow(ip, bucketName string, now time.Time) bool {
	if ip == "" {
		ip = "unknown"
	}

	limit, ok := l.limits[bucketName]
	if !ok {
		limit = l.limits["other"]
	}

	key := bucketName + "|" + ip

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	bucket, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &rateBucket{
			tokens:   limit.burst - 1,
			lastSeen: now,
		}
		return true
	}

	elapsed := now.Sub(bucket.lastSeen).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * limit.refillPerSec
		if bucket.tokens > limit.burst {
			bucket.tokens = limit.burst
		}
	}
	bucket.lastSeen = now

	if bucket.tokens < 1 {
		return false
	}

	bucket.tokens--
	return true
}

func (l *rateLimiter) pruneLocked(now time.Time) {
	for key, bucket := range l.buckets {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			delete(l.buckets, key)
			continue
		}
		limit, ok := l.limits[parts[0]]
		if !ok {
			limit = l.limits["other"]
		}
		if now.Sub(bucket.lastSeen) > limit.cleanupWindow {
			delete(l.buckets, key)
		}
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		styleNonce := randomToken(12)
		csp := strings.Join([]string{
			"default-src 'self'",
			"base-uri 'none'",
			"connect-src 'self' ws: wss:",
			"font-src 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"img-src 'self' data:",
			"object-src 'none'",
			"script-src 'self'",
			fmt.Sprintf("style-src 'self' 'nonce-%s'", styleNonce),
		}, "; ")

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), xr-spatial-tracking=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, styleNonce)))
	})
}

func cspStyleNonce(r *http.Request) string {
	if r == nil {
		return ""
	}
	if value, ok := r.Context().Value(cspNonceKey{}).(string); ok {
		return value
	}
	return ""
}

func withRateLimit(limiter *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		if !limiter.allow(clientIP(r), classifyRoute(r), time.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, errRateLimited.Error(), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func classifyRoute(r *http.Request) string {
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		return "index"
	case r.URL.Path == "/preview.svg" && r.Method == http.MethodGet:
		return "preview"
	case r.URL.Path == "/ui/rooms/create" && r.Method == http.MethodPost:
		return "create"
	case r.URL.Path == "/ui/rooms/join" && r.Method == http.MethodPost:
		return "join"
	case strings.HasPrefix(r.URL.Path, "/api/rooms/") && strings.HasSuffix(r.URL.Path, "/events") && r.Method == http.MethodGet:
		return "events"
	case strings.HasPrefix(r.URL.Path, "/api/rooms/") && strings.HasSuffix(r.URL.Path, "/signal") && r.Method == http.MethodPost:
		return "signal"
	case strings.HasPrefix(r.URL.Path, "/api/rooms/") && strings.HasSuffix(r.URL.Path, "/leave") && r.Method == http.MethodPost:
		return "leave"
	case strings.HasPrefix(r.URL.Path, "/static/") && r.Method == http.MethodGet:
		return "static"
	default:
		return "other"
	}
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")

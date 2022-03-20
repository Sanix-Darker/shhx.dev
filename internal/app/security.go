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


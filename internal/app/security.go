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

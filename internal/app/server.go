package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"shhx.dev/internal/room"
)

//go:embed templates/*.html static
var assets embed.FS

type Server struct {
	hub          *room.Hub
	limiter      *rateLimiter
	templates    *template.Template
	static       http.Handler
	buildVersion string
	ice          *iceConfig
	trustProxy   bool
}

type pageData struct {
	Title          string
	ShareCode      string
	StyleNonce     string
	ICEServers     string
	ProjectVersion string
	PreviewTitle   string
	PreviewDesc    string
	PreviewImage   string
	PreviewURL     string
}

type roomCardData struct {
	RoomCode    string
	Role        string
	PeerID      string
	DisplayName string
}

type ownerRoomEvent struct {
	RoomCode string     `json:"roomCode"`
	Event    room.Event `json:"event"`
}

const defaultICEServersJSON = `[{"urls":["stun:stun.l.google.com:19302"]}]`

const (
	// turnTTLDefaultSeconds is the ephemeral TURN credential lifetime used when
	// SHHX_TURN_TTL_SECONDS is unset or out of range.
	turnTTLDefaultSeconds = 3600
	// turnTTLMinSeconds and turnTTLMaxSeconds bound the accepted TURN TTL.
	turnTTLMinSeconds = 300
	turnTTLMaxSeconds = 86400

	// envICEServers, envTURNSecret, envTURNURIs, and envTURNTTLSeconds name the
	// runtime environment variables that configure ICE/TURN. They are read once
	// at startup, not per request.
	envICEServers     = "SHHX_ICE_SERVERS"
	envTURNSecret     = "SHHX_TURN_SECRET"
	envTURNURIs       = "SHHX_TURN_URIS"
	envTURNTTLSeconds = "SHHX_TURN_TTL_SECONDS"

	// envTrustProxy controls whether X-Forwarded-* headers are honored. It
	// defaults to true so the documented reverse-proxy deployment (Caddy
	// terminating TLS and forwarding over plain HTTP) keeps working. Set it to
	// "false" when the binary is exposed directly so clients cannot spoof their
	// source IP or request scheme.
	envTrustProxy = "SHHX_TRUST_PROXY"
)

// resolveTrustProxy reads SHHX_TRUST_PROXY once at startup. Any value other
// than an explicit disable keeps the default (trust) so existing deployments
// behind a reverse proxy are unaffected.
func resolveTrustProxy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envTrustProxy))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// iceConfig holds ICE/TURN configuration resolved once at startup. The static
// portions (validated JSON, parsed STUN/TURN URIs, secret, TTL) are computed in
// newICEConfig; only the time-based TURN credential is recomputed per render.
type iceConfig struct {
	staticJSON string // pre-validated SHHX_ICE_SERVERS or the built-in default

	turnSecret []byte
	stunURLs   []string
	turnURLs   []string
	turnTTL    time.Duration
}

// newICEConfig reads ICE/TURN environment configuration once. Returning a
// resolved struct keeps env access at the process boundary and avoids
// re-parsing on every index request.
func newICEConfig() *iceConfig {
	cfg := &iceConfig{staticJSON: resolveStaticICEServersJSON()}

	secret := strings.TrimSpace(os.Getenv(envTURNSecret))
	urisRaw := strings.TrimSpace(os.Getenv(envTURNURIs))
	if secret == "" || urisRaw == "" {
		return cfg
	}

	for part := range strings.SplitSeq(urisRaw, ",") {
		uri := strings.TrimSpace(part)
		switch {
		case uri == "":
			continue
		case strings.HasPrefix(uri, "stun:") || strings.HasPrefix(uri, "stuns:"):
			cfg.stunURLs = append(cfg.stunURLs, uri)
		case strings.HasPrefix(uri, "turn:") || strings.HasPrefix(uri, "turns:"):
			cfg.turnURLs = append(cfg.turnURLs, uri)
		}
	}
	if len(cfg.stunURLs) == 0 && len(cfg.turnURLs) == 0 {
		return cfg
	}

	cfg.turnSecret = []byte(secret)
	cfg.turnTTL = turnTTLDefaultSeconds * time.Second
	if raw := strings.TrimSpace(os.Getenv(envTURNTTLSeconds)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= turnTTLMinSeconds && parsed <= turnTTLMaxSeconds {
			cfg.turnTTL = time.Duration(parsed) * time.Second
		}
	}
	return cfg
}

// resolveStaticICEServersJSON validates SHHX_ICE_SERVERS once at startup,
// falling back to the built-in STUN default when unset or invalid.
func resolveStaticICEServersJSON() string {
	value := strings.TrimSpace(os.Getenv(envICEServers))
	if value == "" {
		return defaultICEServersJSON
	}
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(value), &parsed); err != nil || len(parsed) == 0 {
		return defaultICEServersJSON
	}
	return value
}

// serversJSON returns the ICE server list for a page render. When TURN is
// configured it mints a fresh short-lived credential; otherwise it returns the
// pre-validated static JSON without re-reading the environment.
func (c *iceConfig) serversJSON(now time.Time) string {
	if c.turnSecret == nil || (len(c.stunURLs) == 0 && len(c.turnURLs) == 0) {
		return c.staticJSON
	}

	username := fmt.Sprintf("%d:shhx", now.Add(c.turnTTL).Unix())
	mac := hmac.New(sha1.New, c.turnSecret)
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	config := make([]map[string]any, 0, 2)
	if len(c.stunURLs) > 0 {
		config = append(config, map[string]any{"urls": c.stunURLs})
	}
	if len(c.turnURLs) > 0 {
		config = append(config, map[string]any{
			"urls":       c.turnURLs,
			"username":   username,
			"credential": credential,
		})
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return c.staticJSON
	}
	return string(payload)
}

// sseHeartbeatInterval is the keepalive cadence for Server-Sent Events streams.
const sseHeartbeatInterval = 20 * time.Second

// prepareSSEStream sets streaming headers, clears any per-connection write
// deadline so long-lived event streams survive the server WriteTimeout, sends
// the reconnect hint, and returns the flusher. It returns false if the
// ResponseWriter cannot stream, in which case it has already written an error.
func prepareSSEStream(w http.ResponseWriter) (http.Flusher, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return nil, false
	}

	// The HTTP server applies a finite WriteTimeout for normal routes. SSE
	// connections are long-lived, so clear the write deadline for this
	// connection only. Failing to clear it is non-fatal (the stream just
	// inherits the default deadline), so the error is intentionally ignored.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	header.Set("Connection", "keep-alive")
	header.Set("X-Accel-Buffering", "no")

	if _, err := io.WriteString(w, "retry: 2000\n\n"); err != nil {
		return nil, false
	}
	flusher.Flush()
	return flusher, true
}

func NewServer(buildVersion string) (*Server, error) {
	tmpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("static fs: %w", err)
	}

	static, err := newStaticHandler(staticFS)
	if err != nil {
		return nil, fmt.Errorf("load static assets: %w", err)
	}

	return &Server{
		hub:          room.NewHub(),
		limiter:      newRateLimiter(),
		templates:    tmpl,
		static:       static,
		buildVersion: strings.TrimSpace(buildVersion),
		ice:          newICEConfig(),
		trustProxy:   resolveTrustProxy(),
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", s.static))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/preview.svg", s.handlePreviewSVG)
	mux.HandleFunc("/ui/rooms/create", s.handleCreateRoomCard)
	mux.HandleFunc("/ui/rooms/join", s.handleJoinRoomCard)
	mux.HandleFunc("/api/owner/events", s.handleOwnerEvents)
	mux.HandleFunc("/api/rooms/", s.handleRoomAPI)
	return withSecurityHeaders(withRateLimit(s.limiter, s.trustProxy, mux))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := io.WriteString(w, `{"status":"ok"}`+"\n"); err != nil {
		return
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	shareCode, ok := shareCodeFromRequest(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	baseURL := originForRequest(r, s.trustProxy)
	title := "shhx"
	desc := "Create one secret. Share one live encrypted link."
	if shareCode != "" {
		title = "shhx | live encrypted secret vault"
		desc = "Open a live encrypted secret link. The sender must stay online while you read it."
	}

	if err := s.templates.ExecuteTemplate(w, "layout", pageData{
		Title:          "shhx",
		ShareCode:      shareCode,
		StyleNonce:     cspStyleNonce(r),
		ICEServers:     s.ice.serversJSON(time.Now()),
		ProjectVersion: s.buildVersion,
		PreviewTitle:   title,
		PreviewDesc:    desc,
		PreviewImage:   baseURL + "/preview.svg",
		PreviewURL:     baseURL + r.URL.RequestURI(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if _, err := io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="16" fill="#050505"/>
  <rect x="15" y="28" width="34" height="24" rx="6" fill="none" stroke="#F2F2F2" stroke-width="4"/>
  <path d="M22 28v-6c0-6 4-10 10-10s10 4 10 10v6" fill="none" stroke="#F2F2F2" stroke-width="4" stroke-linecap="round"/>
</svg>`); err != nil {
		return
	}
}

func shareCodeFromRequest(r *http.Request) (string, bool) {
	if r.URL.Path == "/" {
		return "", true
	}

	trimmed := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}

	return strings.ToUpper(trimmed), true
}

func (s *Server) handlePreviewSVG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if _, err := io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<svg width="1200" height="630" viewBox="0 0 1200 630" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="1200" height="630" fill="#F7F4ED"/>
  <rect x="68" y="68" width="1064" height="494" rx="42" fill="#FFFCF7" stroke="#D7CEC1"/>
  <circle cx="996" cy="154" r="88" fill="#E5EFE9"/>
  <circle cx="171" cy="123" r="56" fill="#F0E7D9"/>
  <rect x="132" y="158" width="208" height="208" rx="38" fill="#1F6C5C"/>
  <path d="M236 230C236 197.98 210.02 172 178 172C145.98 172 120 197.98 120 230V258H104V352H252V258H236V230ZM150 230C150 214.536 162.536 202 178 202C193.464 202 206 214.536 206 230V258H150V230Z" fill="#F8F4ED"/>
  <text x="390" y="226" fill="#6B625B" font-family="Avenir Next, Segoe UI, sans-serif" font-size="26" letter-spacing="3">SHHX</text>
  <text x="390" y="304" fill="#1E1A17" font-family="Avenir Next, Segoe UI, sans-serif" font-size="64" font-weight="700">Live encrypted secret vault.</text>
  <text x="390" y="366" fill="#1E1A17" font-family="Avenir Next, Segoe UI, sans-serif" font-size="64" font-weight="700">Open the link while the sender stays online.</text>
  <text x="390" y="446" fill="#655D56" font-family="Avenir Next, Segoe UI, sans-serif" font-size="30">Optional OTP protection. No server-side secret storage.</text>
</svg>`); err != nil {
		return
	}
}

func (s *Server) handleCreateRoomCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ensureSameOrigin(r, s.trustProxy); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := requireFormContentType(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	displayName := sanitizeDisplayName(r.FormValue("display_name"))
	requestedRoomCode := strings.ToUpper(strings.TrimSpace(r.FormValue("room_code")))
	if requestedRoomCode != "" && !validRoomCode(requestedRoomCode) {
		http.Error(w, errInvalidRoomCode.Error(), http.StatusBadRequest)
		return
	}
	peerID := randomToken(10)
	roomCode := requestedRoomCode
	if requestedRoomCode != "" {
		if err := s.hub.CreateRoomWithCode(peerID, displayName, requestedRoomCode); err != nil {
			http.Error(w, err.Error(), statusForErr(err))
			return
		}
	} else {
		roomCode = s.hub.CreateRoom(peerID, displayName)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "room-card", roomCardData{
		RoomCode:    roomCode,
		Role:        room.RoleOwner,
		PeerID:      peerID,
		DisplayName: displayName,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleJoinRoomCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ensureSameOrigin(r, s.trustProxy); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := requireFormContentType(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	displayName := sanitizeDisplayName(r.FormValue("display_name"))
	roomCode := strings.ToUpper(strings.TrimSpace(r.FormValue("room_code")))
	if !validRoomCode(roomCode) {
		http.Error(w, errInvalidRoomCode.Error(), http.StatusBadRequest)
		return
	}

	peerID := randomToken(10)
	if err := s.hub.JoinRoom(roomCode, peerID, displayName); err != nil {
		http.Error(w, err.Error(), statusForErr(err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "room-card", roomCardData{
		RoomCode:    roomCode,
		Role:        room.RoleGuest,
		PeerID:      peerID,
		DisplayName: displayName,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleRoomAPI(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/rooms/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}

	roomCode := strings.ToUpper(parts[0])
	if !validRoomCode(roomCode) {
		http.Error(w, errInvalidRoomCode.Error(), http.StatusBadRequest)
		return
	}
	switch parts[1] {
	case "events":
		s.handleEvents(w, r, roomCode)
	case "signal":
		s.handleSignal(w, r, roomCode)
	case "leave":
		s.handleLeave(w, r, roomCode)
	default:
		http.NotFound(w, r)
	}
}

type ownerSubscription struct {
	roomCode string
	peerID   string
}

func parseOwnerSubscriptions(r *http.Request) ([]ownerSubscription, error) {
	raw := r.URL.Query()["sub"]
	if len(raw) == 0 {
		return nil, errInvalidRoomCode
	}

	seen := make(map[string]struct{}, len(raw))
	subs := make([]ownerSubscription, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		roomCode, peerID, ok := strings.Cut(entry, ".")
		if !ok {
			return nil, errInvalidRoomCode
		}
		roomCode = strings.ToUpper(strings.TrimSpace(roomCode))
		peerID = strings.TrimSpace(peerID)
		if !validRoomCode(roomCode) || !validPeerID(peerID) {
			return nil, errInvalidRoomCode
		}
		key := roomCode + "." + peerID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if len(subs) >= maxOwnerSubscriptions {
			return nil, errTooManySubscripts
		}
		subs = append(subs, ownerSubscription{roomCode: roomCode, peerID: peerID})
	}
	if len(subs) == 0 {
		return nil, errInvalidRoomCode
	}
	slices.SortFunc(subs, func(a, b ownerSubscription) int {
		if a.roomCode == b.roomCode {
			return strings.Compare(a.peerID, b.peerID)
		}
		return strings.Compare(a.roomCode, b.roomCode)
	})
	return subs, nil
}

func (s *Server) handleOwnerEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	subs, err := parseOwnerSubscriptions(r)
	if err != nil {
		if errors.Is(err, errTooManySubscripts) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	type activeSub struct {
		roomCode string
		ch       <-chan room.Event
		cleanup  func()
	}

	active := make([]activeSub, 0, len(subs))
	for _, sub := range subs {
		ch, cleanup, subErr := s.hub.Subscribe(sub.roomCode, sub.peerID)
		if subErr != nil {
			continue
		}
		active = append(active, activeSub{
			roomCode: sub.roomCode,
			ch:       ch,
			cleanup:  cleanup,
		})
	}
	if len(active) == 0 {
		http.Error(w, room.ErrRoomNotFound.Error(), http.StatusNotFound)
		return
	}
	defer func() {
		for _, sub := range active {
			sub.cleanup()
		}
	}()

	flusher, ok := prepareSSEStream(w)
	if !ok {
		return
	}

	merged := make(chan ownerRoomEvent, 256)
	ctx := r.Context()
	for _, sub := range active {
		go func(roomCode string, ch <-chan room.Event) {
			for {
				select {
				case <-ctx.Done():
					return
				case evt, ok := <-ch:
					if !ok {
						return
					}
					select {
					case merged <- ownerRoomEvent{RoomCode: roomCode, Event: evt}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(sub.roomCode, sub.ch)
	}

	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case evt := <-merged:
			payload, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, roomCode string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peerID := strings.TrimSpace(r.URL.Query().Get("peer"))
	if !validPeerID(peerID) {
		http.Error(w, errInvalidPeerID.Error(), http.StatusBadRequest)
		return
	}

	ch, cleanup, err := s.hub.Subscribe(roomCode, peerID)
	if err != nil {
		http.Error(w, err.Error(), statusForErr(err))
		return
	}
	defer cleanup()

	flusher, ok := prepareSSEStream(w)
	if !ok {
		return
	}

	ctx := r.Context()
	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case evt, ok := <-ch:
			if !ok {
				return
			}
			payload, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

type signalEnvelope struct {
	From    string          `json:"from"`
	To      string          `json:"to"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Server) handleSignal(w http.ResponseWriter, r *http.Request, roomCode string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ensureSameOrigin(r, s.trustProxy); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := requireJSONContentType(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSignalBodyBytes)
	defer r.Body.Close()
	var envelope signalEnvelope
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if !validPeerID(envelope.From) || (envelope.To != "" && !validPeerID(envelope.To)) {
		http.Error(w, "missing signal fields", http.StatusBadRequest)
		return
	}
	if !validSignalType(envelope.Type) {
		http.Error(w, "missing signal fields", http.StatusBadRequest)
		return
	}
	if len(envelope.Payload) > maxSignalBodyBytes/2 {
		http.Error(w, "signal payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	if err := s.hub.Send(roomCode, envelope.From, envelope.To, envelope.Type, envelope.Payload); err != nil {
		http.Error(w, err.Error(), statusForErr(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleLeave(w http.ResponseWriter, r *http.Request, roomCode string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := ensureSameOrigin(r, s.trustProxy); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	peerID := strings.TrimSpace(r.URL.Query().Get("peer"))
	if !validPeerID(peerID) {
		http.Error(w, errInvalidPeerID.Error(), http.StatusBadRequest)
		return
	}

	s.hub.Leave(roomCode, peerID)
	w.WriteHeader(http.StatusNoContent)
}

func originForRequest(r *http.Request, trustProxy bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if trustProxy {
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
			scheme = forwarded
		}
	}
	return scheme + "://" + r.Host
}

// tokenEncoding produces URL/attribute-safe base32 tokens without padding. It
// is created once and is safe for concurrent use.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return tokenEncoding.EncodeToString(buf)
}

func statusForErr(err error) int {
	switch {
	case errors.Is(err, room.ErrRoomNotFound):
		return http.StatusNotFound
	case errors.Is(err, room.ErrRoomFull):
		return http.StatusConflict
	case errors.Is(err, room.ErrPeerNotFound):
		return http.StatusNotFound
	case errors.Is(err, room.ErrRoomExists):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

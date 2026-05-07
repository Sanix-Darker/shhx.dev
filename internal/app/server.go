package app

import (
	"crypto/rand"
	"embed"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"shhx.dev/internal/room"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	hub       *room.Hub
	limiter   *rateLimiter
	templates *template.Template
	static    http.Handler
}

type pageData struct {
	Title        string
	ShareCode    string
	StyleNonce   string
	PreviewTitle string
	PreviewDesc  string
	PreviewImage string
	PreviewURL   string
}

type roomCardData struct {
	RoomCode    string
	Role        string
	PeerID      string
	DisplayName string
}

func NewServer() (*Server, error) {
	tmpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("static fs: %w", err)
	}

	return &Server{
		hub:       room.NewHub(),
		limiter:   newRateLimiter(),
		templates: tmpl,
		static:    http.FileServer(http.FS(staticFS)),
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", s.static))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/preview.svg", s.handlePreviewSVG)
	mux.HandleFunc("/ui/rooms/create", s.handleCreateRoomCard)
	mux.HandleFunc("/ui/rooms/join", s.handleJoinRoomCard)
	mux.HandleFunc("/api/rooms/", s.handleRoomAPI)
	return withSecurityHeaders(withRateLimit(s.limiter, mux))
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
	baseURL := originForRequest(r)
	title := "shhx"
	desc := "Create one secret. Share one live encrypted link."
	if shareCode != "" {
		title = "shhx | live encrypted secret vault"
		desc = "Open a live encrypted secret link. The sender must stay online while you read it."
	}

	if err := s.templates.ExecuteTemplate(w, "layout", pageData{
		Title:        "shhx",
		ShareCode:    shareCode,
		StyleNonce:   cspStyleNonce(r),
		PreviewTitle: title,
		PreviewDesc:  desc,
		PreviewImage: baseURL + "/preview.svg",
		PreviewURL:   baseURL + r.URL.RequestURI(),
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
	if err := ensureSameOrigin(r); err != nil {
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
	peerID := randomToken(10)
	roomCode := s.hub.CreateRoom(peerID, displayName)

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
	if err := ensureSameOrigin(r); err != nil {
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

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}

	if _, err := io.WriteString(w, "retry: 2000\n\n"); err != nil {
		return
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
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
	if err := ensureSameOrigin(r); err != nil {
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
	if err := ensureSameOrigin(r); err != nil {
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

func originForRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), "=")
}

func statusForErr(err error) int {
	switch {
	case errors.Is(err, room.ErrRoomNotFound):
		return http.StatusNotFound
	case errors.Is(err, room.ErrRoomFull):
		return http.StatusConflict
	case errors.Is(err, room.ErrPeerNotFound):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}

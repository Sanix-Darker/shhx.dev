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

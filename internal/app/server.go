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

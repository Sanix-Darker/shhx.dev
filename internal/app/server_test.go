package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateRoomRejectsOversizedForm(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	body := "display_name=" + strings.Repeat("a", maxFormBodyBytes+64)
	req := httptest.NewRequest(http.MethodPost, "/ui/rooms/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestJoinRoomRejectsInvalidRoomCode(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/rooms/join", strings.NewReader("display_name=Peer&room_code=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestSignalRejectsUnknownFields(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/rooms/ABCD23/signal", strings.NewReader(`{"from":"ABCDEFGH","type":"ready","payload":{},"extra":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"

	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestRateLimitCreateRoute(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	var saw429 bool
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/ui/rooms/create", strings.NewReader("display_name=Sender"))
		req.RemoteAddr = "203.0.113.10:1234"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://example.com")
		req.Host = "example.com"

		rr := httptest.NewRecorder()
		server.Routes().ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}

	if !saw429 {
		t.Fatal("expected rate limiter to trigger")
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("expected csp header")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", rr.Header().Get("X-Frame-Options"))
	}
}

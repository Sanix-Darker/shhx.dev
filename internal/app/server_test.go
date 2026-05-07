package app

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
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

func TestCreateJoinAndSignalFlowOverHTTP(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	roomCode, ownerPeerID := createRoomViaHTTP(t, ts.URL, "Sender")
	ownerEvents, ownerClose := openEventsStream(t, ts.URL, roomCode, ownerPeerID)
	defer ownerClose()

	initial := expectHTTPEvent(t, ownerEvents)
	if initial.Type != "room-state" {
		t.Fatalf("expected owner room-state, got %s", initial.Type)
	}

	_, guestPeerID := joinRoomViaHTTP(t, ts.URL, roomCode, "Recipient")

	joined := expectHTTPEvent(t, ownerEvents)
	if joined.Type != "peer-joined" {
		t.Fatalf("expected peer-joined, got %s", joined.Type)
	}

	guestEvents, guestClose := openEventsStream(t, ts.URL, roomCode, guestPeerID)
	defer guestClose()

	guestInitial := expectHTTPEvent(t, guestEvents)
	if guestInitial.Type != "room-state" {
		t.Fatalf("expected guest room-state, got %s", guestInitial.Type)
	}

	postSignalViaHTTP(t, ts.URL, roomCode, `{"from":"`+ownerPeerID+`","to":"`+guestPeerID+`","type":"ready","payload":{}}`)

	signal := expectHTTPEvent(t, guestEvents)
	if signal.Type != "signal" {
		t.Fatalf("expected signal event, got %s", signal.Type)
	}

	data, ok := signal.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected signal data map, got %T", signal.Data)
	}
	if data["from"] != ownerPeerID || data["to"] != guestPeerID || data["type"] != "ready" {
		t.Fatalf("unexpected signal payload: %#v", data)
	}
}

func TestPreviewGuestDoesNotBlockRealRecipientOverHTTP(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	roomCode, ownerPeerID := createRoomViaHTTP(t, ts.URL, "Sender")
	ownerEvents, ownerClose := openEventsStream(t, ts.URL, roomCode, ownerPeerID)
	defer ownerClose()
	expectHTTPEvent(t, ownerEvents)

	_, previewPeerID := joinRoomViaHTTP(t, ts.URL, roomCode, "Preview")
	previewJoin := expectHTTPEvent(t, ownerEvents)
	if previewJoin.Type != "peer-joined" {
		t.Fatalf("expected preview join event, got %s", previewJoin.Type)
	}

	_, realPeerID := joinRoomViaHTTP(t, ts.URL, roomCode, "Recipient")

	left := expectHTTPEvent(t, ownerEvents)
	if left.Type != "peer-left" {
		t.Fatalf("expected peer-left after orphan preview replacement, got %s", left.Type)
	}
	leftData, ok := left.Data.(map[string]any)
	if !ok || leftData["id"] != previewPeerID {
		t.Fatalf("unexpected peer-left payload: %#v", left.Data)
	}

	realJoin := expectHTTPEvent(t, ownerEvents)
	if realJoin.Type != "peer-joined" {
		t.Fatalf("expected recipient join event, got %s", realJoin.Type)
	}
	joinData, ok := realJoin.Data.(map[string]any)
	if !ok || joinData["id"] != realPeerID {
		t.Fatalf("unexpected peer-joined payload: %#v", realJoin.Data)
	}
}

func TestActiveGuestStillBlocksSecondRecipientOverHTTP(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	roomCode, ownerPeerID := createRoomViaHTTP(t, ts.URL, "Sender")
	ownerEvents, ownerClose := openEventsStream(t, ts.URL, roomCode, ownerPeerID)
	defer ownerClose()
	expectHTTPEvent(t, ownerEvents)

	_, guestPeerID := joinRoomViaHTTP(t, ts.URL, roomCode, "Recipient")
	expectHTTPEvent(t, ownerEvents)

	guestEvents, guestClose := openEventsStream(t, ts.URL, roomCode, guestPeerID)
	defer guestClose()
	expectHTTPEvent(t, guestEvents)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/ui/rooms/join", strings.NewReader("display_name=Extra&room_code="+roomCode))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("second join request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for active room capacity, got %d", resp.StatusCode)
	}
}

var roomCodeRe = regexp.MustCompile(`data-room-code="([A-Z0-9]+)"`)
var peerIDRe = regexp.MustCompile(`data-peer-id="([A-Z0-9]+)"`)

func createRoomViaHTTP(t *testing.T, baseURL, displayName string) (string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/ui/rooms/create", strings.NewReader("display_name="+displayName))
	if err != nil {
		t.Fatalf("new create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", baseURL)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create room request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 creating room, got %d: %s", resp.StatusCode, string(body))
	}
	return parseRoomCardResponse(t, resp.Body)
}

func joinRoomViaHTTP(t *testing.T, baseURL, roomCode, displayName string) (string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/ui/rooms/join", strings.NewReader("display_name="+displayName+"&room_code="+roomCode))
	if err != nil {
		t.Fatalf("new join request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", baseURL)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("join room request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 joining room, got %d: %s", resp.StatusCode, string(body))
	}
	return parseRoomCardResponse(t, resp.Body)
}

func parseRoomCardResponse(t *testing.T, body io.Reader) (string, string) {
	t.Helper()
	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read room card: %v", err)
	}
	roomMatch := roomCodeRe.FindStringSubmatch(string(raw))
	peerMatch := peerIDRe.FindStringSubmatch(string(raw))
	if len(roomMatch) != 2 || len(peerMatch) != 2 {
		t.Fatalf("failed to parse room card attributes from %q", string(raw))
	}
	return roomMatch[1], peerMatch[1]
}

func openEventsStream(t *testing.T, baseURL, roomCode, peerID string) (<-chan eventEnvelope, func()) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/rooms/"+roomCode+"/events?peer="+peerID, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open events stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected 200 opening events stream, got %d: %s", resp.StatusCode, string(body))
	}

	events := make(chan eventEnvelope, 8)
	go func() {
		defer close(events)
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var evt eventEnvelope
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &evt); err != nil {
				continue
			}
			events <- evt
		}
	}()

	return events, func() {
		resp.Body.Close()
	}
}

func postSignalViaHTTP(t *testing.T, baseURL, roomCode, payload string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/rooms/"+roomCode+"/signal", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("new signal request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post signal request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202 posting signal, got %d: %s", resp.StatusCode, string(body))
	}
}

type eventEnvelope struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func expectHTTPEvent(t *testing.T, ch <-chan eventEnvelope) eventEnvelope {
	t.Helper()
	select {
	case evt, ok := <-ch:
		if !ok {
			t.Fatal("event stream closed unexpectedly")
		}
		return evt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for http event")
		return eventEnvelope{}
	}
}

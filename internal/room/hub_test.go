package room

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHubJoinAndSignalFlow(t *testing.T) {
	hub := NewHub()
	roomCode := hub.CreateRoom("owner-1", "Owner")

	ownerEvents, ownerCleanup, err := hub.Subscribe(roomCode, "owner-1")
	if err != nil {
		t.Fatalf("subscribe owner: %v", err)
	}
	defer ownerCleanup()

	initial := expectEvent(t, ownerEvents)
	if initial.Type != "room-state" {
		t.Fatalf("expected room-state, got %s", initial.Type)
	}

	if err := hub.JoinRoom(roomCode, "guest-1", "Guest"); err != nil {
		t.Fatalf("join room: %v", err)
	}

	joined := expectEvent(t, ownerEvents)
	if joined.Type != "peer-joined" {
		t.Fatalf("expected peer-joined, got %s", joined.Type)
	}

	guestEvents, guestCleanup, err := hub.Subscribe(roomCode, "guest-1")
	if err != nil {
		t.Fatalf("subscribe guest: %v", err)
	}
	defer guestCleanup()

	guestInitial := expectEvent(t, guestEvents)
	if guestInitial.Type != "room-state" {
		t.Fatalf("expected guest room-state, got %s", guestInitial.Type)
	}

	payload := json.RawMessage(`{"kind":"offer"}`)
	if err := hub.Send(roomCode, "owner-1", "guest-1", "offer", payload); err != nil {
		t.Fatalf("send signal: %v", err)
	}

	signal := expectEvent(t, guestEvents)
	if signal.Type != "signal" {
		t.Fatalf("expected signal event, got %s", signal.Type)
	}

	data, ok := signal.Data.(SignalData)
	if !ok {
		t.Fatalf("expected SignalData payload, got %T", signal.Data)
	}
	if data.From != "owner-1" || data.To != "guest-1" || data.Type != "offer" {
		t.Fatalf("unexpected signal envelope: %+v", data)
	}
	if string(data.Payload) != string(payload) {
		t.Fatalf("unexpected payload: %s", string(data.Payload))
	}
}

func TestHubRoomCapacity(t *testing.T) {
	hub := NewHub()
	roomCode := hub.CreateRoom("owner-1", "Owner")

	ownerEvents, ownerCleanup, err := hub.Subscribe(roomCode, "owner-1")
	if err != nil {
		t.Fatalf("subscribe owner: %v", err)
	}
	defer ownerCleanup()
	expectEvent(t, ownerEvents)

	if err := hub.JoinRoom(roomCode, "guest-1", "Guest"); err != nil {
		t.Fatalf("first join: %v", err)
	}
	expectEvent(t, ownerEvents)

	guestEvents, guestCleanup, err := hub.Subscribe(roomCode, "guest-1")
	if err != nil {
		t.Fatalf("subscribe guest: %v", err)
	}
	defer guestCleanup()
	expectEvent(t, guestEvents)

	if err := hub.JoinRoom(roomCode, "guest-2", "Extra"); err != ErrRoomFull {
		t.Fatalf("expected ErrRoomFull, got %v", err)
	}
}

func TestHubReplacesOrphanGuest(t *testing.T) {
	hub := NewHub()
	roomCode := hub.CreateRoom("owner-1", "Owner")

	ownerEvents, ownerCleanup, err := hub.Subscribe(roomCode, "owner-1")
	if err != nil {
		t.Fatalf("subscribe owner: %v", err)
	}
	defer ownerCleanup()
	expectEvent(t, ownerEvents)

	if err := hub.JoinRoom(roomCode, "guest-preview", "Preview"); err != nil {
		t.Fatalf("join preview guest: %v", err)
	}
	joined := expectEvent(t, ownerEvents)
	if joined.Type != "peer-joined" {
		t.Fatalf("expected peer-joined for preview, got %s", joined.Type)
	}

	hub.mu.Lock()
	hub.rooms[roomCode].peers["guest-preview"].lastSeen = time.Now().Add(-staleGuestGrace - time.Second)
	hub.mu.Unlock()

	if err := hub.JoinRoom(roomCode, "guest-real", "Recipient"); err != nil {
		t.Fatalf("replace orphan guest: %v", err)
	}

	left := expectEvent(t, ownerEvents)
	if left.Type != "peer-left" {
		t.Fatalf("expected peer-left for orphan guest, got %s", left.Type)
	}
	joined = expectEvent(t, ownerEvents)
	if joined.Type != "peer-joined" {
		t.Fatalf("expected peer-joined for replacement guest, got %s", joined.Type)
	}

	guestEvents, guestCleanup, err := hub.Subscribe(roomCode, "guest-real")
	if err != nil {
		t.Fatalf("subscribe replacement guest: %v", err)
	}
	defer guestCleanup()
	expectEvent(t, guestEvents)
}

func TestHubRemovesGuestWhenLastStreamCloses(t *testing.T) {
	hub := NewHub()
	roomCode := hub.CreateRoom("owner-1", "Owner")

	ownerEvents, ownerCleanup, err := hub.Subscribe(roomCode, "owner-1")
	if err != nil {
		t.Fatalf("subscribe owner: %v", err)
	}
	defer ownerCleanup()
	expectEvent(t, ownerEvents)

	if err := hub.JoinRoom(roomCode, "guest-1", "Guest"); err != nil {
		t.Fatalf("join room: %v", err)
	}
	expectEvent(t, ownerEvents)

	guestEvents, guestCleanup, err := hub.Subscribe(roomCode, "guest-1")
	if err != nil {
		t.Fatalf("subscribe guest: %v", err)
	}
	expectEvent(t, guestEvents)

	guestCleanup()

	left := expectEvent(t, ownerEvents)
	if left.Type != "peer-left" {
		t.Fatalf("expected peer-left after guest cleanup, got %s", left.Type)
	}

	if err := hub.JoinRoom(roomCode, "guest-2", "Replacement"); err != nil {
		t.Fatalf("join replacement guest: %v", err)
	}
}

func TestHubLeaveDeletesEmptyRoom(t *testing.T) {
	hub := NewHub()
	roomCode := hub.CreateRoom("owner-1", "Owner")

	hub.Leave(roomCode, "owner-1")

	if _, _, err := hub.Subscribe(roomCode, "owner-1"); err != ErrRoomNotFound {
		t.Fatalf("expected room deletion, got %v", err)
	}
}

func TestHubRejectsJoinWhenOwnerWentStale(t *testing.T) {
	hub := NewHub()
	roomCode := hub.CreateRoom("owner-1", "Owner")

	ownerEvents, ownerCleanup, err := hub.Subscribe(roomCode, "owner-1")
	if err != nil {
		t.Fatalf("subscribe owner: %v", err)
	}
	expectEvent(t, ownerEvents)
	ownerCleanup()

	hub.mu.Lock()
	hub.rooms[roomCode].peers["owner-1"].lastSeen = time.Now().Add(-staleOwnerGrace - time.Second)
	hub.mu.Unlock()

	if err := hub.JoinRoom(roomCode, "guest-1", "Guest"); err != ErrRoomNotFound {
		t.Fatalf("expected ErrRoomNotFound for stale owner room, got %v", err)
	}
}

func TestHubPruneExpiredRooms(t *testing.T) {
	hub := NewHub()
	hub.roomTTL = time.Minute

	roomCode := hub.CreateRoom("owner-1", "Owner")

	hub.mu.Lock()
	hub.rooms[roomCode].lastActive = time.Now().Add(-2 * time.Minute)
	hub.mu.Unlock()

	hub.pruneExpired(time.Now())

	if _, _, err := hub.Subscribe(roomCode, "owner-1"); err != ErrRoomNotFound {
		t.Fatalf("expected room pruning, got %v", err)
	}
}

func expectEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case evt := <-ch:
		return evt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
		return Event{}
	}
}

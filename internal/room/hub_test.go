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


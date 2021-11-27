package room

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const (
	RoleOwner = "owner"
	RoleGuest = "guest"
)

var (
	ErrRoomNotFound = errors.New("room not found")
	ErrRoomFull     = errors.New("room already has two peers")
	ErrPeerNotFound = errors.New("peer not found")
)

type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type PeerSnapshot struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
}

type SignalData struct {
	From    string          `json:"from"`
	To      string          `json:"to"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type subscription struct {
	ch chan Event
}

type peer struct {
	id          string
	displayName string
	role        string
	streams     map[*subscription]struct{}
}

type roomState struct {
	code       string
	peers      map[string]*peer
	createdAt  time.Time
	lastActive time.Time
}

type Hub struct {
	mu      sync.RWMutex
	rooms   map[string]*roomState
	roomTTL time.Duration
}

func NewHub() *Hub {
	hub := &Hub{
		rooms:   make(map[string]*roomState),
		roomTTL: 30 * time.Minute,
	}
	go hub.startJanitor()
	return hub
}

func (h *Hub) CreateRoom(ownerID, displayName string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	code := randomCodeLocked(h.rooms)
	now := time.Now()
	state := &roomState{
		code:       code,
		peers:      make(map[string]*peer),
		createdAt:  now,
		lastActive: now,
	}
	state.peers[ownerID] = &peer{
		id:          ownerID,
		displayName: displayName,
		role:        RoleOwner,
		streams:     make(map[*subscription]struct{}),
	}
	h.rooms[code] = state
	return code
}

func (h *Hub) JoinRoom(code, peerID, displayName string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	state, ok := h.rooms[code]
	if !ok {
		return ErrRoomNotFound
	}
	if len(state.peers) >= 2 {
		return ErrRoomFull
	}
	state.lastActive = time.Now()
	state.peers[peerID] = &peer{
		id:          peerID,
		displayName: displayName,
		role:        RoleGuest,
		streams:     make(map[*subscription]struct{}),
	}
	h.broadcastLocked(state, Event{
		Type: "peer-joined",
		Data: PeerSnapshot{ID: peerID, DisplayName: displayName, Role: RoleGuest},
	})
	return nil
}

func (h *Hub) Subscribe(code, peerID string) (<-chan Event, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	state, ok := h.rooms[code]
	if !ok {
		return nil, nil, ErrRoomNotFound
	}
	p, ok := state.peers[peerID]
	if !ok {
		return nil, nil, ErrPeerNotFound
	}
	state.lastActive = time.Now()

	sub := &subscription{ch: make(chan Event, 32)}
	p.streams[sub] = struct{}{}

	peers := make([]PeerSnapshot, 0, len(state.peers))
	for _, candidate := range state.peers {
		peers = append(peers, PeerSnapshot{
			ID:          candidate.id,
			DisplayName: candidate.displayName,
			Role:        candidate.role,
		})
	}
	sub.ch <- Event{Type: "room-state", Data: peers}

	cleanup := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if state, ok := h.rooms[code]; ok {
			if peer, ok := state.peers[peerID]; ok {
				delete(peer.streams, sub)
			}
		}
		close(sub.ch)
	}

	return sub.ch, cleanup, nil
}

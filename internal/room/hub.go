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
	joinedAt    time.Time
	lastSeen    time.Time
	engaged     bool
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

const staleGuestGrace = 3 * time.Second
const staleOwnerGrace = 5 * time.Second

const StaleOwnerGraceForTest = staleOwnerGrace

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
		joinedAt:    now,
		lastSeen:    now,
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
	h.evictStaleOwnersLocked(code, state, time.Now())
	if _, ok := h.rooms[code]; !ok {
		return ErrRoomNotFound
	}
	h.evictOrphanGuestsLocked(state)
	h.evictStaleGuestsLocked(state, time.Now())
	if len(state.peers) >= 2 {
		return ErrRoomFull
	}
	now := time.Now()
	state.lastActive = now
	state.peers[peerID] = &peer{
		id:          peerID,
		displayName: displayName,
		role:        RoleGuest,
		streams:     make(map[*subscription]struct{}),
		joinedAt:    now,
		lastSeen:    now,
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
	p.lastSeen = state.lastActive

	sub := &subscription{ch: make(chan Event, 128)}
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
				peer.lastSeen = time.Now()
				if peer.role == RoleGuest && len(peer.streams) == 0 {
					delete(state.peers, peerID)
					state.lastActive = time.Now()
					h.broadcastLocked(state, Event{
						Type: "peer-left",
						Data: map[string]string{"id": peerID},
					})
					if len(state.peers) == 0 {
						delete(h.rooms, code)
					}
				}
			}
		}
		close(sub.ch)
	}

	return sub.ch, cleanup, nil
}

func (h *Hub) Send(code, from, to, signalType string, payload json.RawMessage) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	state, ok := h.rooms[code]
	if !ok {
		return ErrRoomNotFound
	}
	sender, ok := state.peers[from]
	if !ok {
		return ErrPeerNotFound
	}
	state.lastActive = time.Now()
	sender.lastSeen = state.lastActive
	sender.engaged = true

	evt := Event{
		Type: "signal",
		Data: SignalData{
			From:    from,
			To:      to,
			Type:    signalType,
			Payload: payload,
		},
	}

	if to != "" {
		peer, ok := state.peers[to]
		if !ok {
			return ErrPeerNotFound
		}
		for sub := range peer.streams {
			select {
			case sub.ch <- evt:
			default:
			}
		}
		return nil
	}

	for id, peer := range state.peers {
		if id == from {
			continue
		}
		for sub := range peer.streams {
			select {
			case sub.ch <- evt:
			default:
			}
		}
	}

	return nil
}

func (h *Hub) Leave(code, peerID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	state, ok := h.rooms[code]
	if !ok {
		return
	}
	if _, ok := state.peers[peerID]; !ok {
		return
	}

	delete(state.peers, peerID)
	state.lastActive = time.Now()
	h.broadcastLocked(state, Event{
		Type: "peer-left",
		Data: map[string]string{"id": peerID},
	})

	if len(state.peers) == 0 {
		delete(h.rooms, code)
	}
}

func (h *Hub) evictOrphanGuestsLocked(state *roomState) {
	for id, peer := range state.peers {
		if peer.role != RoleGuest {
			continue
		}
		if len(peer.streams) > 0 {
			continue
		}
		delete(state.peers, id)
		h.broadcastLocked(state, Event{
			Type: "peer-left",
			Data: map[string]string{"id": id},
		})
	}
}

func (h *Hub) evictStaleOwnersLocked(code string, state *roomState, now time.Time) {
	for id, peer := range state.peers {
		if peer.role != RoleOwner {
			continue
		}
		if len(peer.streams) > 0 {
			continue
		}
		if now.Sub(peer.lastSeen) < staleOwnerGrace {
			continue
		}
		delete(h.rooms, code)
		delete(state.peers, id)
		for _, otherPeer := range state.peers {
			for sub := range otherPeer.streams {
				close(sub.ch)
			}
		}
		return
	}
}

func (h *Hub) evictStaleGuestsLocked(state *roomState, now time.Time) {
	for id, peer := range state.peers {
		if peer.role != RoleGuest || peer.engaged {
			continue
		}
		if now.Sub(peer.lastSeen) < staleGuestGrace {
			continue
		}
		delete(state.peers, id)
		h.broadcastLocked(state, Event{
			Type: "peer-left",
			Data: map[string]string{"id": id},
		})
	}
}

func (h *Hub) broadcastLocked(state *roomState, evt Event) {
	for _, peer := range state.peers {
		for sub := range peer.streams {
			select {
			case sub.ch <- evt:
			default:
			}
		}
	}
}

func (h *Hub) startJanitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.pruneExpired(time.Now())
	}
}

func (h *Hub) pruneExpired(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for code, state := range h.rooms {
		if now.Sub(state.lastActive) > h.roomTTL {
			for _, peer := range state.peers {
				for sub := range peer.streams {
					close(sub.ch)
				}
			}
			delete(h.rooms, code)
		}
	}
}

func randomCodeLocked(existing map[string]*roomState) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for {
		buf := make([]byte, 6)
		raw := make([]byte, 6)
		if _, err := rand.Read(raw); err != nil {
			panic(err)
		}
		for i := range buf {
			buf[i] = alphabet[int(raw[i])%len(alphabet)]
		}
		code := string(buf)
		if _, ok := existing[code]; !ok {
			return code
		}
	}
}

func (h *Hub) ForcePeerLastSeenForTest(code, peerID string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if state, ok := h.rooms[code]; ok {
		if peer, ok := state.peers[peerID]; ok {
			peer.lastSeen = at
		}
	}
}

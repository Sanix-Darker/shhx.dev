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

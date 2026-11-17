package main

import (
	"encoding/json"
	"sync"
	"time"
)

const (
	heartbeatEvery = 20 * time.Second
	deadAfter      = 45 * time.Second
	sendQueue      = 32
)

// client is one live WebSocket. Outbound messages go through a bounded queue;
// a client that cannot keep up is dropped and will resync on reconnect.
type client struct {
	ws   *wsConn
	send chan []byte
	done chan struct{}
	once sync.Once
}

func (c *client) stop() {
	c.once.Do(func() {
		close(c.done)
		c.ws.close()
	})
}

type hub struct {
	mu      sync.Mutex
	clients map[string]*client
}

func newHub() *hub { return &hub{clients: map[string]*client{}} }

// attach registers c for the device, evicting any previous connection
// (max 1 connection per device).
func (h *hub) attach(id string, c *client) {
	h.mu.Lock()
	old := h.clients[id]
	h.clients[id] = c
	h.mu.Unlock()
	if old != nil {
		old.stop()
	}
}

func (h *hub) detach(id string, c *client) {
	h.mu.Lock()
	if h.clients[id] == c {
		delete(h.clients, id)
	}
	h.mu.Unlock()
	c.stop()
}

// push queues a message for the device. Returns false if nobody is connected
// or the client was too slow (and got dropped).
func (h *hub) push(id string, msg any) bool {
	b, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	h.mu.Lock()
	c := h.clients[id]
	h.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case c.send <- b:
		return true
	default:
		h.detach(id, c)
		return false
	}
}

func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

type event struct {
	Type         string `json:"type"`
	ChatID       string `json:"chatId,omitempty"`
	MessageID    string `json:"messageId,omitempty"`
	HeartbeatSec int    `json:"heartbeatSec,omitempty"`
}

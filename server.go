package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type server struct {
	store       *store
	hub         *hub
	inviteToken string // if set, /register requires "Authorization: Bearer <it>"
	trustProxy  bool   // use rightmost X-Forwarded-For as client IP
	regLimit    *limiter
	hookLimit   *limiter
}

func newServer(st *store, invite string, trustProxy bool) *server {
	return &server{
		store:       st,
		hub:         newHub(),
		inviteToken: invite,
		trustProxy:  trustProxy,
		regLimit:    newLimiter(5.0/60, 5), // 5 per minute per IP
		hookLimit:   newLimiter(20, 100),   // per device
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /ws", s.handleWS)
	mux.HandleFunc("POST /hook/{deviceId}", func(w http.ResponseWriter, r *http.Request) {
		s.handleGraph(w, r, false)
	})
	mux.HandleFunc("POST /lifecycle/{deviceId}", func(w http.ResponseWriter, r *http.Request) {
		s.handleGraph(w, r, true)
	})
	return mux
}

func (s *server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.regLimit.allow(s.clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if s.inviteToken != "" &&
		subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.inviteToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, secret, cs, err := s.store.register()
	if errors.Is(err, errFull) {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	} else if err != nil {
		log.Printf("register: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("registered device %s", id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"deviceId": id, "deviceSecret": secret, "clientState": cs,
	})
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("deviceId")
	if !s.store.authenticate(id, bearer(r)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := upgrade(w, r)
	if err != nil {
		return // upgrade already replied or hijacked
	}
	c := &client{ws: ws, send: make(chan []byte, sendQueue), done: make(chan struct{})}
	s.hub.attach(id, c)
	defer s.hub.detach(id, c)
	log.Printf("ws connect %s", id)
	defer log.Printf("ws disconnect %s", id)

	c.send <- mustJSON(event{Type: "hello", HeartbeatSec: int(heartbeatEvery / time.Second)})

	// Reader: any frame (pong included) proves liveness; silence for
	// deadAfter kills the connection.
	go func() {
		defer c.stop()
		for {
			ws.c.SetReadDeadline(time.Now().Add(deadAfter))
			op, payload, err := ws.readFrame()
			if err != nil {
				return
			}
			switch op {
			case opPing:
				ws.writeFrame(opPong, payload)
			case opClose:
				ws.writeFrame(opClose, nil)
				return
			}
		}
	}()

	tick := time.NewTicker(heartbeatEvery)
	defer tick.Stop()
	for {
		select {
		case <-c.done:
			return
		case b := <-c.send:
			if ws.writeFrame(opText, b) != nil {
				return
			}
		case <-tick.C:
			if ws.writeFrame(opPing, nil) != nil ||
				ws.writeFrame(opText, mustJSON(event{Type: "heartbeat"})) != nil {
				return
			}
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

type notification struct {
	SubscriptionID string `json:"subscriptionId"`
	ClientState    string `json:"clientState"`
	ChangeType     string `json:"changeType"`
	Resource       string `json:"resource"`
	LifecycleEvent string `json:"lifecycleEvent"`
	ResourceData   struct {
		ID string `json:"id"`
	} `json:"resourceData"`
}

var (
	resParen = regexp.MustCompile(`chats\('([^']+)'\)/messages\('([^']+)'\)`)
	resSlash = regexp.MustCompile(`chats/([^/]+)/messages/([^/?]+)`)
)

// parseResource extracts chat and message ids from a Graph resource string.
func parseResource(res, fallbackMsg string) (chat, msg string, ok bool) {
	m := resParen.FindStringSubmatch(res)
	if m == nil {
		m = resSlash.FindStringSubmatch(res)
	}
	if m == nil {
		return "", "", false
	}
	msg = m[2]
	if msg == "" {
		msg = fallbackMsg
	}
	return m[1], msg, true
}

func (s *server) handleGraph(w http.ResponseWriter, r *http.Request, lifecycle bool) {
	id := r.PathValue("deviceId")
	dev, ok := s.store.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Subscription validation handshake: echo the token as text/plain.
	if tok := r.URL.Query().Get("validationToken"); tok != "" {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		io.WriteString(w, tok)
		return
	}
	if !s.hookLimit.allow(id) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var payload struct {
		Value []notification `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	// Acknowledge first (Graph wants a fast 202), forward after.
	w.WriteHeader(http.StatusAccepted)

	seen := map[string]bool{}
	for _, n := range payload.Value {
		if subtle.ConstantTimeCompare([]byte(n.ClientState), []byte(dev.ClientState)) != 1 {
			log.Printf("drop notification for %s: clientState mismatch", id)
			continue
		}
		if lifecycle || n.LifecycleEvent != "" {
			switch n.LifecycleEvent {
			case "missed":
				s.hub.push(id, event{Type: "resync"})
			case "reauthorizationRequired", "subscriptionRemoved":
				s.hub.push(id, event{Type: "reauth"})
			}
			continue
		}
		chat, msg, ok := parseResource(n.Resource, n.ResourceData.ID)
		if !ok {
			continue
		}
		if k := chat + "\x00" + msg; !seen[k] {
			seen[k] = true
			s.hub.push(id, event{Type: "message", ChatID: chat, MessageID: msg})
		}
	}
}

// limiter is a per-key token bucket.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	bucket map[string]*bucketState
	last   time.Time // last sweep
}

type bucketState struct {
	tokens float64
	at     time.Time
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, bucket: map[string]*bucketState{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.last) > time.Minute { // drop idle, full buckets
		for k, b := range l.bucket {
			if now.Sub(b.at) > time.Minute {
				delete(l.bucket, k)
			}
		}
		l.last = now
	}
	b := l.bucket[key]
	if b == nil {
		b = &bucketState{tokens: l.burst, at: now}
		l.bucket[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

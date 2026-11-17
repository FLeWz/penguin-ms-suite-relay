package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// device is what the relay remembers per client. The secret is stored only as
// a SHA-256 hash. ClientState is the value the client must put in the Graph
// subscription; the relay compares it on every notification.
type device struct {
	SecretHash  string `json:"secretHash"`
	ClientState string `json:"clientState"`
}

type store struct {
	mu      sync.RWMutex
	path    string // "" = memory only
	max     int
	devices map[string]device
}

func newStore(path string, max int) (*store, error) {
	s := &store{path: path, max: max, devices: map[string]device{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.devices); err != nil {
		return nil, err
	}
	return s, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var errFull = errors.New("device limit reached")

// register creates a device and returns its credentials.
func (s *store) register() (id, secret, clientState string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.devices) >= s.max {
		return "", "", "", errFull
	}
	id, secret, clientState = randHex(16), randHex(32), randHex(16)
	s.devices[id] = device{SecretHash: hashSecret(secret), ClientState: clientState}
	if err = s.saveLocked(); err != nil {
		delete(s.devices, id)
		return "", "", "", err
	}
	return
}

func (s *store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(s.devices)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *store) get(id string) (device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	return d, ok
}

// authenticate checks a device secret in constant time.
func (s *store) authenticate(id, secret string) bool {
	d, ok := s.get(id)
	if !ok {
		d.SecretHash = hashSecret("") // compare anyway: similar timing for unknown ids
	}
	eq := subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(d.SecretHash)) == 1
	return ok && eq
}

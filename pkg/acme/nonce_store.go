package acme

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceStore is a thread-safe store for nonces
type NonceStore struct {
	nonces map[string]time.Time
	mu     sync.Mutex
	ttl    time.Duration
}

// NewNonceStore initializes a new NonceStore with a specified TTL (Time-To-Live)
func NewNonceStore(ttl time.Duration) *NonceStore {
	store := &NonceStore{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
	}

	// Start a background goroutine to clean up expired nonces periodically
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			<-ticker.C
			store.sweep()
		}
	}()

	return store
}

// Add inserts a new nonce into the store with the current timestamp
func (s *NonceStore) Add(nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = time.Now()
}

// Exists checks if a nonce exists and is still valid (not expired)
// Returns true if valid, false otherwise
func (s *NonceStore) Exists(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, exists := s.nonces[nonce]
	if !exists {
		return false
	}
	if time.Since(ts) > s.ttl {
		delete(s.nonces, nonce)
		return false
	}
	// Optionally delete the nonce after it's used to enforce single use
	delete(s.nonces, nonce)
	return true
}

// sweep removes expired nonces from the store
func (s *NonceStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for nonce, ts := range s.nonces {
		if now.Sub(ts) > s.ttl {
			delete(s.nonces, nonce)
		}
	}
}

// GenerateNonce creates a new secure random nonce encoded in URL-safe Base64 without padding
func GenerateNonce(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// ACME nonces are URL-safe base64 without padding
	return base64.RawURLEncoding.EncodeToString(b), nil
}

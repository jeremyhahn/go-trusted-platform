// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package configdelivery

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	nonceLength     = 32 // bytes
	defaultNonceTTL = 5 * time.Minute
)

// NonceStore manages short-lived nonces for replay prevention.
type NonceStore struct {
	nonces map[string]time.Time
	mu     sync.Mutex
	ttl    time.Duration
}

// NewNonceStore creates a new NonceStore with the given TTL.
func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
	}
}

// Issue generates a new random nonce and stores it.
func (ns *NonceStore) Issue() (string, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.cleanup()

	buf := make([]byte, nonceLength)
	if _, err := rand.Read(buf); err != nil {
		return "", ErrNonceGenerationFailed{Cause: err}
	}

	nonce := hex.EncodeToString(buf)
	ns.nonces[nonce] = time.Now().Add(ns.ttl)

	return nonce, nil
}

// Validate checks if a nonce is valid and removes it (single-use).
// Returns false if the nonce is unknown, expired, or already used.
func (ns *NonceStore) Validate(nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.cleanup()

	expiresAt, ok := ns.nonces[nonce]
	if !ok {
		return false
	}

	delete(ns.nonces, nonce)

	return time.Now().Before(expiresAt)
}

// cleanup removes expired nonces. Must be called with the lock held.
func (ns *NonceStore) cleanup() {
	now := time.Now()
	for nonce, expiresAt := range ns.nonces {
		if now.After(expiresAt) {
			delete(ns.nonces, nonce)
		}
	}
}

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

package adminclaim

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// secretBytes is the length of a challenge nonce and of a claim token. 32
// bytes is the full output of the SHA-256-class CSPRNG draw used below and
// leaves no useful margin for guessing within a two-minute window.
const secretBytes = 32

// maxOutstanding caps how many unspent secrets the store will hold. The
// claim endpoints are reachable before any session exists, so an unbounded
// map would be a memory-exhaustion target. Reaching the cap is refused,
// never silently evicted: evicting would let an attacker flush the
// operator's live challenge and force them to restart the ceremony.
const maxOutstanding = 64

// entry is one issued secret. Value is opaque to the store; the service
// uses it to carry the verified identity from a proof to the enrollment
// that follows it.
type entry struct {
	value     string
	expiresAt time.Time
}

// secretStore issues, redeems and expires single-use, short-lived secrets.
//
// **The secret itself is never retained.** Entries are keyed by the
// SHA-256 digest of the secret, and presented secrets are hashed before
// lookup. A claim token authorises enrolling an administrative
// authenticator, and Go strings cannot be wiped, so holding one verbatim
// would leave a live bearer credential recoverable from process memory
// for as long as the heap keeps the page. The digest is useless to an
// attacker who reads it: it cannot be presented.
//
// Redemption is atomic: sync.Map's LoadAndDelete resolves exactly one
// winner however many callers race for the same secret, so a leaked
// challenge or claim token cannot be replayed even under concurrency.
// Secrets live only in this process — a restart invalidates every
// outstanding one, which is the safe direction for a bootstrap ceremony.
type secretStore struct {
	entries     sync.Map // sha256(secret) -> entry
	outstanding atomic.Int64
	ttl         time.Duration
	// now is injected so tests can drive expiry without sleeping.
	now func() time.Time
}

func newSecretStore(ttl time.Duration) *secretStore {
	return &secretStore{ttl: ttl, now: time.Now}
}

// issue mints a new secret carrying value, returning it and its expiry.
//
// The slot is RESERVED atomically before anything is generated or stored,
// and handed back on refusal or failure. A check-then-increment would let
// any number of concurrent callers all observe the count below the cap and
// all go on to store — and these endpoints are reachable pre-auth, so that
// burst is exactly the memory-exhaustion the cap exists to prevent. The
// counter may momentarily read above the cap while losers give their slot
// back; the number of STORED entries never does.
func (s *secretStore) issue(value string) (string, time.Time, error) {
	s.sweep()
	if s.outstanding.Add(1) > maxOutstanding {
		s.outstanding.Add(-1)
		return "", time.Time{}, ErrTooManyOutstanding{Limit: maxOutstanding}
	}
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		s.outstanding.Add(-1)
		return "", time.Time{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := s.now().Add(s.ttl)
	s.entries.Store(digest(secret), entry{value: value, expiresAt: expiresAt})
	return secret, expiresAt, nil
}

// digest is the lookup key for a secret: its SHA-256, hex-encoded. The
// store never holds the secret itself.
func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// redeem consumes a secret, returning its carried value. A secret that is
// unknown, already redeemed or expired reports ok=false — the three are
// deliberately indistinguishable to the caller.
func (s *secretStore) redeem(secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	raw, ok := s.entries.LoadAndDelete(digest(secret))
	if !ok {
		return "", false
	}
	s.outstanding.Add(-1)
	e := raw.(entry)
	if s.now().After(e.expiresAt) {
		return "", false
	}
	return e.value, true
}

// peek reports the value carried by a secret WITHOUT consuming it. It
// backs the multi-step passkey ceremony, where begin must not spend the
// token that finish still needs.
func (s *secretStore) peek(secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	raw, ok := s.entries.Load(digest(secret))
	if !ok {
		return "", false
	}
	e := raw.(entry)
	if s.now().After(e.expiresAt) {
		return "", false
	}
	return e.value, true
}

// sweep drops expired entries so a burst of abandoned challenges cannot
// hold the store at its cap until process exit.
func (s *secretStore) sweep() {
	now := s.now()
	s.entries.Range(func(k, v any) bool {
		if now.After(v.(entry).expiresAt) {
			if _, deleted := s.entries.LoadAndDelete(k); deleted {
				s.outstanding.Add(-1)
			}
		}
		return true
	})
}

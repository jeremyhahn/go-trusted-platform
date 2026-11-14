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

package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrTokenRevoked is returned by Verify for a token that was signed out
// (#215). It is a distinct error so a caller can tell a revoked session
// from a forged or expired one in its logs; on the wire both are 401.
var ErrTokenRevoked = errors.New("rest/jwt: token revoked")

// revocationList is the server-side deny-list that makes logout real
// (#215). Before it, logout only deleted the browser cookie: the token
// itself stayed valid until it expired, so a copy of it (another tab, a
// script, anything that had read it) kept working after the user signed
// out.
//
// An entry is keyed by the token's "jti" and lives only until the token
// would have expired anyway, so the list holds at most the sessions
// signed out within one token lifetime. A token minted before tokens
// carried a "jti" is keyed by a digest of its compact form instead, so
// signing out revokes it too.
//
// The list is per process. A deployment that runs several platformd
// instances behind one console must share it before logout holds across
// instances; that is reported on #215, not papered over here.
type revocationList struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// revocationKey names the token a revocation applies to.
func revocationKey(token *jwt.Token) string {
	if claims, ok := token.Claims.(*TokenClaims); ok && claims.ID != "" {
		return "jti:" + claims.ID
	}
	sum := sha256.Sum256([]byte(token.Raw))
	return "raw:" + hex.EncodeToString(sum[:])
}

// revocationExpiry is when an entry may be forgotten: the token's own
// expiry. A token with no expiry is remembered for the life of the
// process (the zero time).
func revocationExpiry(token *jwt.Token) time.Time {
	if claims, ok := token.Claims.(*TokenClaims); ok && claims.ExpiresAt != nil {
		return claims.ExpiresAt.Time
	}
	return time.Time{}
}

// revoke records the token and forgets every entry whose token has
// expired, so the list cannot grow past one token lifetime of sign-outs.
func (list *revocationList) revoke(token *jwt.Token, now time.Time) {
	list.mu.Lock()
	defer list.mu.Unlock()
	if list.entries == nil {
		list.entries = make(map[string]time.Time)
	}
	for key, expiry := range list.entries {
		if !expiry.IsZero() && expiry.Before(now) {
			delete(list.entries, key)
		}
	}
	list.entries[revocationKey(token)] = revocationExpiry(token)
}

// revoked reports whether the token was signed out.
func (list *revocationList) revoked(token *jwt.Token) bool {
	list.mu.Lock()
	defer list.mu.Unlock()
	_, ok := list.entries[revocationKey(token)]
	return ok
}

// newTokenID mints a token's "jti": 128 random bits, hex encoded. Every
// token the platform signs carries one, so two tokens minted for the same
// user in the same second are still distinct, and signing one out does
// not sign out the other.
func newTokenID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		// crypto/rand does not fail on a supported platform; if it ever
		// does, a token without a jti is still revocable by its digest.
		return ""
	}
	return hex.EncodeToString(id[:])
}

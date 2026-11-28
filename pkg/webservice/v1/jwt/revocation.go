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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// ErrTokenRevoked is returned by Verify for a token that was signed out
// (#215). It is a distinct error so a caller can tell a revoked session
// from a forged or expired one in its logs; on the wire both are 401.
var ErrTokenRevoked = errors.New("rest/jwt: token revoked")

// ErrRevocationUnavailable wraps a revocation store that cannot be read or
// written (#646). Verify still fails closed on it, and Logout answers it
// with 503 rather than 401: the bearer is not refused, the server simply
// could not record its revocation, so the client can retry.
var ErrRevocationUnavailable = errors.New("rest/jwt: revocation store unavailable")

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
// The list is per process: it is the fallback a Service uses only when it
// is given no RevocationStore (tests, a daemon with no store). The daemon
// wires the persistent BlobRevocationStore, so logout holds across
// restarts and across every instance sharing the store.
type revocationList struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// revocationKey names the token a revocation applies to.
func revocationKey(token *jwt.Token) string {
	if claims, ok := token.Claims.(*TokenClaims); ok && claims.ID != "" {
		return "jti:" + claims.ID
	}
	// A token issued before jti existed is keyed by its signing input
	// (header.payload, exactly as signed), never by its signature: ECDSA
	// signatures are malleable, (r, s) -> (r, N-s) verifies without the
	// key, so a key over the signature would let a copy survive logout.
	signingInput := token.Raw
	if dot := strings.LastIndexByte(signingInput, '.'); dot >= 0 {
		signingInput = signingInput[:dot]
	}
	sum := sha256.Sum256([]byte(signingInput))
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

// sessionRevocationKey names the login session a token belongs to, or ""
// for a token without a session id (issued before the claim existed),
// which is revoked by revocationKey alone (#1906).
func sessionRevocationKey(token *jwt.Token) string {
	if claims, ok := token.Claims.(*TokenClaims); ok && claims.SessionID != "" {
		return "sid:" + claims.SessionID
	}
	return ""
}

// sessionRevocationExpiry is when a session's revocation may be
// forgotten: every token of the session was minted at or before now, so
// none outlives now plus the token lifetime, nor the presented token's
// own expiry. Zero (never) when neither is known.
func sessionRevocationExpiry(token *jwt.Token, lifetime time.Duration, now time.Time) time.Time {
	expiry := revocationExpiry(token)
	if lifetime <= 0 {
		return expiry
	}
	// A refresh re-checks the session after its IAM read, but it signs
	// a moment later: a token it mints just after this logout expires
	// after now+lifetime, so the revocation stands a refresh window
	// longer than the lifetime (#1906 Codex).
	if bound := now.Add(lifetime + sessionRefreshWindow); expiry.IsZero() || bound.After(expiry) {
		return bound
	}
	return expiry
}

// sessionRefreshWindow bounds the time between a refresh's last
// revocation check and the signing of the token it mints.
const sessionRefreshWindow = time.Minute

// revoke records the token and forgets every entry whose token has
// expired, so the list cannot grow past one token lifetime of sign-outs.
func (list *revocationList) revoke(token *jwt.Token, now time.Time) {
	_ = list.Revoke(context.Background(), revocationKey(token), revocationExpiry(token), now)
}

// revoked reports whether the token was signed out.
func (list *revocationList) revoked(token *jwt.Token) bool {
	revoked, _ := list.Revoked(context.Background(), revocationKey(token), time.Now())
	return revoked
}

// Revoke implements RevocationStore in process memory.
func (list *revocationList) Revoke(_ context.Context, key string, expiry, now time.Time) error {
	list.mu.Lock()
	defer list.mu.Unlock()
	if list.entries == nil {
		list.entries = make(map[string]time.Time)
	}
	for entry, until := range list.entries {
		if !until.IsZero() && until.Before(now) {
			delete(list.entries, entry)
		}
	}
	list.entries[key] = expiry
	return nil
}

// Revoked implements RevocationStore in process memory.
func (list *revocationList) Revoked(_ context.Context, key string, _ time.Time) (bool, error) {
	list.mu.Lock()
	defer list.mu.Unlock()
	_, ok := list.entries[key]
	return ok, nil
}

// RevocationStore holds the logout deny-list (#215). Revoke records a
// token's revocation key until expiry (the zero time: no expiry); Revoked
// reports whether a key was revoked. An error from Revoked fails
// verification closed.
type RevocationStore interface {
	Revoke(ctx context.Context, key string, expiry, now time.Time) error
	Revoked(ctx context.Context, key string, now time.Time) (bool, error)
}

// RevocationBlobs is the part of the daemon's persistent blob DAO (the
// WebAuthn session store the service registry exposes) a
// BlobRevocationStore needs.
type RevocationBlobs interface {
	Get(ctx context.Context, id uint64) (*entities.Blob, error)
	Save(ctx context.Context, blob *entities.Blob) error
	Delete(ctx context.Context, blob *entities.Blob) error
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Blob], error)
}

// revocationBlobKind tags a revocation record, so a blob of another kind
// that happens to share an id is never read as a revocation.
const revocationBlobKind = "jwt-revocation"

type revocationRecord struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Expires int64  `json:"expires"` // Unix seconds; 0: no expiry
}

// BlobRevocationStore keeps revocations in the daemon's persistent store,
// so a signed-out token stays refused after a restart and on every
// platformd instance sharing that store. A record lives until the token's
// own expiry. An expired token is refused before revocation is consulted,
// so expired records are removed by the sweep each logout runs (at most
// once per revocationSweepInterval), and also when one is looked up.
type BlobRevocationStore struct {
	blobs RevocationBlobs

	// mu guards lastSweep.
	mu sync.Mutex
	// lastSweep is when the last successful sweep ran; zero until then.
	lastSweep time.Time
}

// revocationSweepInterval is the least time between two sweeps the logout
// path runs.
const revocationSweepInterval = time.Hour

// revocationSweepPageSize is how many blobs a sweep reads per page.
const revocationSweepPageSize = 100

// Sweep deletes every revocation record that expired before now and
// returns how many it deleted. WebAuthn session blobs and revocations
// with no expiry are never touched. It reads every page before deleting,
// so its deletes never shift the pages it reads.
func (store *BlobRevocationStore) Sweep(ctx context.Context, now time.Time) (int, error) {
	var expired []*entities.Blob
	for page := 1; ; page++ {
		result, err := store.blobs.Page(ctx, datastore.PageQuery{
			Page: page, PageSize: revocationSweepPageSize, SortOrder: datastore.SortAscending,
		})
		if err != nil {
			return 0, fmt.Errorf("%w: sweep: %w", ErrRevocationUnavailable, err)
		}
		for _, blob := range result.Entities {
			if blob == nil {
				continue
			}
			var record revocationRecord
			if json.Unmarshal(blob.Bytes, &record) != nil ||
				record.Kind != revocationBlobKind || blob.ID != revocationBlobID(record.Key) {
				continue
			}
			if record.Expires != 0 && time.Unix(record.Expires, 0).Before(now) {
				expired = append(expired, blob)
			}
		}
		if !result.HasMore || len(result.Entities) == 0 {
			break
		}
	}
	deleted := 0
	for _, blob := range expired {
		if err := store.blobs.Delete(ctx, blob); err != nil {
			return deleted, fmt.Errorf("%w: sweep: %w", ErrRevocationUnavailable, err)
		}
		deleted++
	}
	return deleted, nil
}

// NewBlobRevocationStore returns a RevocationStore over blobs.
func NewBlobRevocationStore(blobs RevocationBlobs) *BlobRevocationStore {
	return &BlobRevocationStore{blobs: blobs}
}

// revocationBlobID derives a record's id from its revocation key.
func revocationBlobID(key string) uint64 {
	sum := sha256.Sum256([]byte(revocationBlobKind + "\x00" + key))
	id := binary.BigEndian.Uint64(sum[:8])
	if id == 0 {
		id = 1 // 0 asks the DAO to mint an id
	}
	return id
}

// Revoke implements RevocationStore.
func (store *BlobRevocationStore) Revoke(ctx context.Context, key string, expiry, now time.Time) error {
	record := revocationRecord{Kind: revocationBlobKind, Key: key}
	if !expiry.IsZero() {
		record.Expires = expiry.Unix()
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := store.blobs.Save(ctx, entities.NewBlob(revocationBlobID(key), bytes)); err != nil {
		return fmt.Errorf("%w: save: %w", ErrRevocationUnavailable, err)
	}
	// Only a logout adds a record, so sweeping on the logout path bounds
	// the store; the first logout after a restart sweeps the records an
	// earlier process left. A failed sweep does not fail the logout (the
	// record is saved) and the next Revoke retries it.
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lastSweep.IsZero() || now.Sub(store.lastSweep) >= revocationSweepInterval {
		if _, err := store.Sweep(ctx, now); err == nil {
			store.lastSweep = now
		}
	}
	return nil
}

// Revoked implements RevocationStore.
func (store *BlobRevocationStore) Revoked(ctx context.Context, key string, now time.Time) (bool, error) {
	blob, err := store.blobs.Get(ctx, revocationBlobID(key))
	if errors.Is(err, datastore.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: lookup: %w", ErrRevocationUnavailable, err)
	}
	var record revocationRecord
	if json.Unmarshal(blob.Bytes, &record) != nil ||
		record.Kind != revocationBlobKind || record.Key != key {
		return false, nil
	}
	if record.Expires != 0 && time.Unix(record.Expires, 0).Before(now) {
		_ = store.blobs.Delete(ctx, blob)
		return false, nil
	}
	return true, nil
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

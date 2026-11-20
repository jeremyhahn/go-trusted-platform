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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	qbstore "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryBlobs stands in for the daemon's persistent blob DAO: it outlives
// every Service and store built over it, as the database does a restart.
type memoryBlobs struct {
	mu    sync.Mutex
	blobs map[uint64][]byte
	fail  error
	// miss, when set, is the error Get returns for an absent blob, so a
	// test can answer with a production DAO's own not-found type.
	miss error
	// pages counts Page calls: one per page a sweep reads.
	pages int
}

func (m *memoryBlobs) Page(_ context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Blob], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pages++
	if m.fail != nil {
		return datastore.PageResult[*entities.Blob]{}, m.fail
	}
	ids := make([]uint64, 0, len(m.blobs))
	for id := range m.blobs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	start := (query.Page - 1) * query.PageSize
	if start < 0 || start > len(ids) {
		start = len(ids)
	}
	end := min(start+query.PageSize, len(ids))
	result := datastore.PageResult[*entities.Blob]{
		Page: query.Page, PageSize: query.PageSize, Total: len(ids), HasMore: end < len(ids),
	}
	for _, id := range ids[start:end] {
		result.Entities = append(result.Entities, entities.NewBlob(id, append([]byte(nil), m.blobs[id]...)))
	}
	return result, nil
}

// seedRevocation stores a revocation record as an earlier process left it.
func seedRevocation(t *testing.T, blobs *memoryBlobs, key string, expires time.Time) {
	t.Helper()
	record := revocationRecord{Kind: revocationBlobKind, Key: key}
	if !expires.IsZero() {
		record.Expires = expires.Unix()
	}
	bytes, err := json.Marshal(record)
	require.NoError(t, err)
	blobs.mu.Lock()
	defer blobs.mu.Unlock()
	if blobs.blobs == nil {
		blobs.blobs = make(map[uint64][]byte)
	}
	blobs.blobs[revocationBlobID(key)] = bytes
}

// stored reports whether a blob with id is still in the store.
func (m *memoryBlobs) stored(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.blobs[id]
	return ok
}

func (m *memoryBlobs) Get(_ context.Context, id uint64) (*entities.Blob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	bytes, ok := m.blobs[id]
	if !ok {
		if m.miss != nil {
			return nil, m.miss
		}
		return nil, datastore.ErrRecordNotFound
	}
	return entities.NewBlob(id, append([]byte(nil), bytes...)), nil
}

func (m *memoryBlobs) Save(_ context.Context, blob *entities.Blob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	if m.blobs == nil {
		m.blobs = make(map[uint64][]byte)
	}
	m.blobs[blob.ID] = append([]byte(nil), blob.Bytes...)
	return nil
}

func (m *memoryBlobs) Delete(_ context.Context, blob *entities.Blob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs, blob.ID)
	return nil
}

// servicesOverOneKey builds two Services that share a signing key, each
// with its own revocation store over the same backing blobs: two platformd
// instances, or one instance before and after a restart.
func servicesOverOneKey(t *testing.T, blobs *memoryBlobs) (*Service, *Service) {
	t.Helper()
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	params.Revocations = NewBlobRevocationStore(blobs)
	first, err := NewService(context.Background(), params)
	require.NoError(t, err)
	params.Revocations = NewBlobRevocationStore(blobs)
	second, err := NewService(context.Background(), params)
	require.NoError(t, err)
	return first, second
}

func verifyString(service *Service, bearer string) error {
	token, err := service.ParseTokenString(bearer)
	if err != nil {
		return err
	}
	return service.Verify(token)
}

// A logout recorded by one instance holds on another instance and after a
// restart: the revocation lives in the shared store, not in process memory.
func TestRevocation_PersistsAcrossStoresOverTheSameBackend(t *testing.T) {
	t.Parallel()
	blobs := &memoryBlobs{}
	issuer, other := servicesOverOneKey(t, blobs)

	bearer, err := issuer.GenerateToken(entities.NewUser("revoked@example.com"))
	require.NoError(t, err)
	kept, err := issuer.GenerateToken(entities.NewUser("kept@example.com"))
	require.NoError(t, err)
	require.NoError(t, verifyString(other, bearer), "the second instance accepts the token before logout")

	token, err := issuer.ParseTokenString(bearer)
	require.NoError(t, err)
	require.NoError(t, issuer.Revoke(token))

	require.ErrorIs(t, verifyString(issuer, bearer), ErrTokenRevoked)
	require.ErrorIs(t, verifyString(other, bearer), ErrTokenRevoked,
		"another instance over the same store refuses the signed-out token")
	require.NoError(t, verifyString(other, kept), "a session that was not signed out stays valid")
}

// A token issued before jti existed is keyed by what was signed, not by its
// signature: ECDSA signatures are malleable ((r, s) -> (r, N-s) verifies
// without the key), so a copy with the other signature must stay revoked.
func TestRevocation_LegacyTokenWithMalleatedSignatureStaysRevoked(t *testing.T) {
	t.Parallel()
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs = &xkmssdk.KeyAttributes{
		CN:                 "ES256-legacy",
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            xkmssdk.KeyTypeTLS,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		StoreType:          xkmssdk.StoreSoftware,
		ECCAttributes:      &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)
	blobs := &memoryBlobs{}
	params.Revocations = NewBlobRevocationStore(blobs)
	issuer, err := NewService(context.Background(), params)
	require.NoError(t, err)
	params.Revocations = NewBlobRevocationStore(blobs)
	other, err := NewService(context.Background(), params)
	require.NoError(t, err)
	pub, ok := issuer.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok, "the test key is ECDSA")

	now := time.Now()
	legacy, err := jwt.NewWithClaims(issuer.signingMethod, TokenClaims{
		UID: "7", TenantID: "default",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "7",
			Audience:  jwt.ClaimStrings{"localhost"},
			Issuer:    "localhost",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}).SignedString(issuer.signer)
	require.NoError(t, err)

	dot := strings.LastIndex(legacy, ".")
	raw, err := base64.RawURLEncoding.DecodeString(legacy[dot+1:])
	require.NoError(t, err)
	size := (pub.Curve.Params().BitSize + 7) / 8
	require.Len(t, raw, 2*size, "a JWS ECDSA signature is r||s")
	s := new(big.Int).SetBytes(raw[size:])
	flipped := new(big.Int).Sub(pub.Curve.Params().N, s).FillBytes(make([]byte, size))
	malleated := legacy[:dot+1] + base64.RawURLEncoding.EncodeToString(append(slices.Clone(raw[:size]), flipped...))
	require.NotEqual(t, legacy, malleated)
	require.NoError(t, verifyString(other, malleated), "the malleated signature verifies")

	token, err := issuer.ParseTokenString(legacy)
	require.NoError(t, err)
	require.NoError(t, issuer.Revoke(token))

	require.ErrorIs(t, verifyString(issuer, legacy), ErrTokenRevoked)
	require.ErrorIs(t, verifyString(issuer, malleated), ErrTokenRevoked,
		"a malleated copy of a signed-out legacy token is refused")
	require.ErrorIs(t, verifyString(other, malleated), ErrTokenRevoked)
}

// The sweep removes expired revocation records and nothing else: not a
// live revocation, not one with no expiry, not another kind of blob.
func TestBlobRevocationStore_SweepDeletesOnlyExpiredRevocations(t *testing.T) {
	t.Parallel()
	blobs := &memoryBlobs{}
	seedRevocation(t, blobs, "expired", time.Now().Add(-time.Hour))
	seedRevocation(t, blobs, "live", time.Now().Add(time.Hour))
	seedRevocation(t, blobs, "forever", time.Time{})
	const sessionID = uint64(42)
	blobs.blobs[sessionID] = []byte("webauthn-session")

	swept, err := NewBlobRevocationStore(blobs).Sweep(context.Background(), time.Now())

	require.NoError(t, err)
	require.Equal(t, 1, swept)
	require.False(t, blobs.stored(revocationBlobID("expired")), "the expired record is deleted")
	require.True(t, blobs.stored(revocationBlobID("live")), "a live revocation stays")
	require.True(t, blobs.stored(revocationBlobID("forever")), "a revocation with no expiry stays")
	require.True(t, blobs.stored(sessionID), "a WebAuthn session blob is never touched")
}

// An expired token never reaches Revoked, so its record would stay for
// good; the logout path sweeps what an earlier process left behind.
func TestRevocation_ALogoutSweepsExpiredRecordsAnEarlierProcessLeft(t *testing.T) {
	t.Parallel()
	blobs := &memoryBlobs{}
	seedRevocation(t, blobs, "left-by-an-earlier-process", time.Now().Add(-time.Hour))
	const sessionID = uint64(42)
	blobs.blobs[sessionID] = []byte("webauthn-session")
	issuer, other := servicesOverOneKey(t, blobs)

	bearer, err := issuer.GenerateToken(entities.NewUser("revoked@example.com"))
	require.NoError(t, err)
	token, err := issuer.ParseTokenString(bearer)
	require.NoError(t, err)
	require.NoError(t, issuer.Revoke(token))

	require.False(t, blobs.stored(revocationBlobID("left-by-an-earlier-process")),
		"the logout swept the expired record")
	require.ErrorIs(t, verifyString(other, bearer), ErrTokenRevoked, "the new revocation holds")
	require.True(t, blobs.stored(sessionID), "the sweep leaves other blobs alone")
}

// The logout path sweeps at most once per interval.
func TestBlobRevocationStore_SweepsAtMostOncePerInterval(t *testing.T) {
	t.Parallel()
	blobs := &memoryBlobs{}
	store := NewBlobRevocationStore(blobs)
	now := time.Now()
	expiry := now.Add(time.Hour)
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "first", expiry, now))
	require.NoError(t, store.Revoke(ctx, "second", expiry, now))
	require.Equal(t, 1, blobs.pages, "the second logout within the interval does not sweep")

	require.NoError(t, store.Revoke(ctx, "third", expiry, now.Add(revocationSweepInterval)))
	require.Equal(t, 2, blobs.pages, "a logout after the interval sweeps again")
}

// A store that cannot answer fails verification closed: a signed-out token
// is never accepted because the deny-list was unreachable.
func TestRevocation_UnreachableStoreFailsClosed(t *testing.T) {
	t.Parallel()
	blobs := &memoryBlobs{}
	issuer, _ := servicesOverOneKey(t, blobs)
	bearer, err := issuer.GenerateToken(entities.NewUser("closed@example.com"))
	require.NoError(t, err)

	blobs.mu.Lock()
	blobs.fail = errors.New("store down")
	blobs.mu.Unlock()
	err = verifyString(issuer, bearer)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrTokenRevoked)
	require.ErrorIs(t, err, ErrRevocationUnavailable)
}

// The production blob DAOs answer a miss with their own ErrNotFound types,
// not the bare datastore sentinel. A token that was never revoked must still
// verify over either of them, and a revoked one must still be refused.
func TestRevocation_ProductionDAOMissIsNotRevoked(t *testing.T) {
	t.Parallel()
	for name, miss := range map[string]error{
		"quicbaas": qbstore.ErrNotFound{EntityType: "Blob", ID: 1},
		"kvstore":  kvstore.ErrNotFound{EntityType: "Blob", ID: 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			blobs := &memoryBlobs{miss: miss}
			issuer, other := servicesOverOneKey(t, blobs)

			bearer, err := issuer.GenerateToken(entities.NewUser("fresh@example.com"))
			require.NoError(t, err)
			token, err := issuer.ParseTokenString(bearer)
			require.NoError(t, err)

			revoked, err := NewBlobRevocationStore(blobs).Revoked(context.Background(), revocationKey(token), time.Now())
			require.NoError(t, err, "a DAO miss is not a lookup failure")
			require.False(t, revoked)
			require.NoError(t, verifyString(other, bearer), "a never-revoked token verifies")

			require.NoError(t, issuer.Revoke(token))
			require.ErrorIs(t, verifyString(other, bearer), ErrTokenRevoked)
		})
	}
}

// TestRevocation_ARefreshInFlightAcrossALogoutMintsNoLiveToken pins #1906
// Codex P1: a refresh that passed its revocation check before a logout but
// mints after it must not produce a token that outlives the revocation.
func TestRevocation_ARefreshInFlightAcrossALogoutMintsNoLiveToken(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	principals := &blockingPrincipals{
		fakePrincipals: fakePrincipals{tenants: map[string]map[string][]string{
			"tenant-a": {backboneSubject: {"admin"}},
		}},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	handler.SetPrincipalResolver(principals)

	a := issueBackboneBearer(t, handler)
	type result struct {
		code    int
		payload string
	}
	done := make(chan result, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.RefreshToken(rec, bearerRequest(http.MethodPost, "/login/refresh", a))
		var env struct {
			Payload string `json:"payload"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		done <- result{code: rec.Code, payload: env.Payload}
	}()

	// The refresh has passed its revocation check and is reading IAM.
	<-principals.entered
	require.Equal(t, http.StatusOK, logout(handler, a).Code)
	close(principals.release)
	got := <-done

	assert.NotEqual(t, http.StatusOK, got.code,
		"a refresh in flight across the logout minted a token of the signed-out session")
	if got.payload != "" {
		_, reached := verifyThrough(handler, got.payload)
		assert.False(t, reached, "the token a refresh minted after the logout authenticates")
	}
}

// TestRevocation_ASessionRevocationOutlivesATokenMintedJustAfterTheLogout
// pins the expiry side of #1906 Codex P1: a refresh that passed its last
// revocation check just before the logout signs a token whose expiry is
// later than logout+lifetime; the session revocation must stand until that
// token has expired too, at and after logout+lifetime.
func TestRevocation_ASessionRevocationOutlivesATokenMintedJustAfterTheLogout(t *testing.T) {
	t.Parallel()
	lifetime := 15 * time.Minute
	logoutAt := time.Unix(1_700_000_000, 0)
	presented := &jwt.Token{Claims: jwt.MapClaims{
		"exp": float64(logoutAt.Add(time.Minute).Unix()),
	}}
	expiry := sessionRevocationExpiry(presented, lifetime, logoutAt)
	// A token minted up to a minute after the logout expires at
	// mintedAt+lifetime; the revocation must still stand then.
	mintedAt := logoutAt.Add(time.Minute)
	assert.False(t, expiry.Before(mintedAt.Add(lifetime)),
		"the session revocation expires at %s, before a token minted at %s (expiring %s)",
		expiry, mintedAt, mintedAt.Add(lifetime))
}

// blockingPrincipals holds a backbone refresh inside its IAM read until
// the test releases it.
type blockingPrincipals struct {
	fakePrincipals
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingPrincipals) Principal(ctx context.Context, tenantID, subject string) ([]string, bool, error) {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return p.fakePrincipals.Principal(ctx, tenantID, subject)
}

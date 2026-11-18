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
	"errors"
	"sync"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	qbstore "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
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

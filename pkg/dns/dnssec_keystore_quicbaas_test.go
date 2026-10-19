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

package dns

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKMS generates keys by name and records every delete. Methods the key
// store does not call are left to the embedded nil interface.
type fakeKMS struct {
	kms.Client
	deleteErr error
	deleted   []string
	getErr    error
	publicDER []byte
}

// GetPublicKey returns the DER-encoded public key, as the KMS does.
func (f *fakeKMS) GetPublicKey(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &kms.GetPublicKeyResponse{KeyID: keyID, PublicKey: f.publicDER}, nil
}

func (f *fakeKMS) GenerateKey(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	return &kms.GenerateKeyResponse{KeyID: req.Name, Algorithm: req.Algorithm}, nil
}

func (f *fakeKMS) DeleteKey(ctx context.Context, keyID string) error {
	f.deleted = append(f.deleted, keyID)
	return f.deleteErr
}

type fakeSecurity struct {
	quicbaas.SecurityService
	kms *fakeKMS
}

func (f fakeSecurity) KMS() quicbaas.KMSClient { return f.kms }

// fakeKV records every metadata write.
type fakeKV struct {
	quicbaas.KVClient
	putErr error
	puts   []*service.PutRequest
}

func (f *fakeKV) Put(ctx context.Context, req *service.PutRequest) (*service.PutResponse, error) {
	f.puts = append(f.puts, req)
	return nil, f.putErr
}

type fakeKeyStoreClient struct {
	quicbaas.Client
	security fakeSecurity
	kv       *fakeKV
}

func (f fakeKeyStoreClient) Security() quicbaas.SecurityService { return f.security }
func (f fakeKeyStoreClient) KV() quicbaas.KVClient              { return f.kv }

var (
	errTestGet    = errors.New("kms get public key failed")
	errTestPut    = errors.New("kv put failed")
	errTestDelete = errors.New("kms delete failed")
)

// newECDSAKMS returns a fake KMS whose keys have the public half of a fresh
// P-256 key, and that public key.
func newECDSAKMS(t *testing.T) (*fakeKMS, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return &fakeKMS{publicDER: publicDER}, &key.PublicKey
}

func newTestKeyStore(t *testing.T, k *fakeKMS, kv *fakeKV) *QuicBaaSKMSKeyStore {
	t.Helper()
	store, err := NewQuicBaaSKMSKeyStore(fakeKeyStoreClient{
		security: fakeSecurity{kms: k},
		kv:       kv,
	})
	require.NoError(t, err)
	return store
}

// newFailingKeyStore returns a key store whose metadata write fails.
func newFailingKeyStore(t *testing.T, deleteErr error) (*QuicBaaSKMSKeyStore, *fakeKMS) {
	t.Helper()
	k, _ := newECDSAKMS(t)
	k.deleteErr = deleteErr
	return newTestKeyStore(t, k, &fakeKV{putErr: errTestPut}), k
}

// generations covers both key-generation paths that clean up after a
// failure: the metadata write fails in each.
func generations(t *testing.T) map[string]func(context.Context, *QuicBaaSKMSKeyStore) error {
	t.Helper()
	return map[string]func(context.Context, *QuicBaaSKMSKeyStore) error{
		"GenerateKSK": func(ctx context.Context, s *QuicBaaSKMSKeyStore) error {
			_, err := s.GenerateKSK(ctx, "tenant", "example.com.", dns.ECDSAP256SHA256)
			return err
		},
		"GenerateZSK": func(ctx context.Context, s *QuicBaaSKMSKeyStore) error {
			_, err := s.GenerateZSK(ctx, "tenant", "example.com.", dns.ECDSAP256SHA256)
			return err
		},
	}
}

func TestQuicBaaSKMSKeyStore_FailedStepDeletesTheKey(t *testing.T) {
	for name, generate := range generations(t) {
		t.Run(name, func(t *testing.T) {
			store, k := newFailingKeyStore(t, nil)

			err := generate(context.Background(), store)

			require.Error(t, err)
			assert.ErrorIs(t, err, errTestPut)
			var cleanup *CleanupError
			assert.False(t, errors.As(err, &cleanup), "a successful delete adds nothing to the error")
			assert.Len(t, k.deleted, 1, "the KMS key the failed generation created is deleted")
		})
	}
}

func TestQuicBaaSKMSKeyStore_FailedDeleteIsReported(t *testing.T) {
	for name, generate := range generations(t) {
		t.Run(name, func(t *testing.T) {
			store, _ := newFailingKeyStore(t, errTestDelete)

			err := generate(context.Background(), store)

			var dnssecErr *DNSSECError
			require.ErrorAs(t, err, &dnssecErr)
			var cleanup *CleanupError
			require.ErrorAs(t, err, &cleanup, "the orphaned KMS key must be reported")
			assert.ErrorIs(t, err, errTestPut, "the original failure is kept")
			assert.ErrorIs(t, err, errTestDelete, "the delete failure is kept")
		})
	}
}

func TestCleanupError(t *testing.T) {
	err := &CleanupError{Err: errTestPut, Cleanup: errTestDelete}
	assert.Equal(t, "kv put failed (cleanup failed: kms delete failed)", err.Error())
	assert.ErrorIs(t, err, errTestPut)
	assert.ErrorIs(t, err, errTestDelete)
}

func TestQuicBaaSKMSKeyStore_GenerateKSKPublishesTheKMSPublicKey(t *testing.T) {
	k, pub := newECDSAKMS(t)
	kv := &fakeKV{}
	store := newTestKeyStore(t, k, kv)

	dnskey, err := store.GenerateKSK(context.Background(), "tenant", "example.com.", dns.ECDSAP256SHA256)

	require.NoError(t, err)
	assert.Equal(t, ecdsaPublicKeyToBase64(pub), dnskey.PublicKey, "the DNSKEY must carry the key the KMS signs with")
	assert.Equal(t, uint16(dns.ZONE|dns.SEP), dnskey.Flags)
	assert.Len(t, kv.puts, 1, "the key metadata is stored")
	assert.Empty(t, k.deleted)
}

func TestQuicBaaSKMSKeyStore_UnavailablePublicKeyDeletesTheKey(t *testing.T) {
	tests := map[string]struct {
		getErr    error
		publicDER []byte
		want      []error
	}{
		"GetPublicKey fails": {getErr: errTestGet, want: []error{ErrKMSKeyNotFound, errTestGet}},
		"empty public key":   {want: []error{ErrKMSKeyNotFound}},
		"unparsable DER":     {publicDER: []byte("not DER")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			k := &fakeKMS{getErr: tc.getErr, publicDER: tc.publicDER}
			kv := &fakeKV{}
			store := newTestKeyStore(t, k, kv)

			_, err := store.GenerateZSK(context.Background(), "tenant", "example.com.", dns.ECDSAP256SHA256)

			var dnssecErr *DNSSECError
			require.ErrorAs(t, err, &dnssecErr)
			for _, want := range tc.want {
				assert.ErrorIs(t, err, want)
			}
			assert.Len(t, k.deleted, 1, "the KMS key without a usable public key is deleted")
			assert.Empty(t, kv.puts, "no metadata is stored for a deleted key")
		})
	}
}

func TestQuicBaaSKMSKeyStore_FailedDNSKEYBuildDeletesTheKey(t *testing.T) {
	// X25519 parses as a PKIX public key but cannot be a DNSKEY.
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(x25519.PublicKey())
	require.NoError(t, err)
	k := &fakeKMS{publicDER: publicDER}
	kv := &fakeKV{}
	store := newTestKeyStore(t, k, kv)

	_, err = store.GenerateKSK(context.Background(), "tenant", "example.com.", dns.ECDSAP256SHA256)

	var dnssecErr *DNSSECError
	require.ErrorAs(t, err, &dnssecErr)
	assert.Len(t, k.deleted, 1, "the KMS key is deleted when its DNSKEY cannot be built")
	assert.Empty(t, kv.puts, "the metadata is written only after the DNSKEY is built")
}

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

package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIAKTPM answers IAKAttributes with a fixed result.
type fakeIAKTPM struct {
	attrs *xkmssdk.KeyAttributes
	err   error
}

func (f *fakeIAKTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) { return f.attrs, f.err }

// fakeTPMCertStore is a TPM certificate store keyed the way the real
// adapter keys it: by attrs.CN. Errors injected per operation stand in
// for a failing object store.
type fakeTPMCertStore struct {
	certs   map[string]*x509.Certificate
	getErr  error
	saveErr error
	saved   []string
}

func newFakeTPMCertStore() *fakeTPMCertStore {
	return &fakeTPMCertStore{certs: map[string]*x509.Certificate{}}
}

func (f *fakeTPMCertStore) Get(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	cert, ok := f.certs[attrs.CN]
	if !ok {
		return nil, xkmssdk.ErrTPMStoreCertNotFound
	}
	return cert, nil
}

func (f *fakeTPMCertStore) Save(attrs *xkmssdk.KeyAttributes, cert *x509.Certificate) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.certs[attrs.CN] = cert
	f.saved = append(f.saved, attrs.CN)
	return nil
}

func (f *fakeTPMCertStore) Delete(attrs *xkmssdk.KeyAttributes) error {
	delete(f.certs, attrs.CN)
	return nil
}

func (f *fakeTPMCertStore) ImportCertificate(attrs *xkmssdk.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	return nil, errors.New("not used by the migration")
}

// selfSignedCert issues a certificate for a fresh ECDSA key and returns it
// with the key's PKIX encoding, the form TPMAttributes.PublicKeyBytes holds.
func selfSignedCert(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return cert, pub
}

func iakAttrsFor(cn string, pub []byte) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{CN: cn, TPMAttributes: &xkmssdk.TPMAttributes{PublicKeyBytes: pub}}
}

func TestMigrateInterimIAKCertificate_Migrates(t *testing.T) {
	cert, pub := selfSignedCert(t, "node-07-iak")
	store := newFakeTPMCertStore()
	store.certs[interimIAKCN] = cert
	tpm := &fakeIAKTPM{attrs: iakAttrsFor("node-07-iak", pub)}

	migrated, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

	require.NoError(t, err)
	assert.True(t, migrated)
	assert.Same(t, cert, store.certs["node-07-iak"], "the certificate is stored under the IAK's CN")
	assert.Same(t, cert, store.certs[interimIAKCN], "the interim entry is left in place")
	assert.Equal(t, []string{"node-07-iak"}, store.saved)

	// A second boot finds the new name and does nothing.
	migrated, err = migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())
	require.NoError(t, err)
	assert.False(t, migrated)
	assert.Equal(t, []string{"node-07-iak"}, store.saved, "no second write")
}

func TestMigrateInterimIAKCertificate_NothingToMigrate(t *testing.T) {
	cert, pub := selfSignedCert(t, "node-07-iak")

	t.Run("no IAK handle: the node was never provisioned", func(t *testing.T) {
		store := newFakeTPMCertStore()
		store.certs[interimIAKCN] = cert
		tpm := &fakeIAKTPM{err: errors.New("handle not found")}

		migrated, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

		require.NoError(t, err)
		assert.False(t, migrated)
		assert.Empty(t, store.saved)
	})

	t.Run("nothing stored under the interim name", func(t *testing.T) {
		store := newFakeTPMCertStore()
		tpm := &fakeIAKTPM{attrs: iakAttrsFor("node-07-iak", pub)}

		migrated, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

		require.NoError(t, err)
		assert.False(t, migrated)
		assert.Empty(t, store.saved)
	})

	t.Run("the IAK is still named by the interim default", func(t *testing.T) {
		store := newFakeTPMCertStore()
		store.certs[interimIAKCN] = cert
		tpm := &fakeIAKTPM{attrs: iakAttrsFor(interimIAKCN, pub)}

		migrated, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

		require.NoError(t, err)
		assert.False(t, migrated)
		assert.Empty(t, store.saved)
	})

	t.Run("nil TPM or store", func(t *testing.T) {
		migrated, err := migrateInterimIAKCertificate(nil, newFakeTPMCertStore(), logging.DefaultLogger())
		require.NoError(t, err)
		assert.False(t, migrated)

		migrated, err = migrateInterimIAKCertificate(&fakeIAKTPM{attrs: iakAttrsFor("node-07-iak", pub)}, nil, logging.DefaultLogger())
		require.NoError(t, err)
		assert.False(t, migrated)
	})
}

func TestMigrateInterimIAKCertificate_ForeignCertificateIsNotAdopted(t *testing.T) {
	foreign, _ := selfSignedCert(t, "some-other-device")
	_, pub := selfSignedCert(t, "node-07-iak")
	store := newFakeTPMCertStore()
	store.certs[interimIAKCN] = foreign
	tpm := &fakeIAKTPM{attrs: iakAttrsFor("node-07-iak", pub)}

	migrated, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

	require.NoError(t, err, "a mismatch is logged, not fatal")
	assert.False(t, migrated)
	assert.Empty(t, store.saved, "a certificate for another key is never stored under this IAK's name")
	_, hasNew := store.certs["node-07-iak"]
	assert.False(t, hasNew)
}

func TestMigrateInterimIAKCertificate_StoreErrors(t *testing.T) {
	cert, pub := selfSignedCert(t, "node-07-iak")
	tpm := &fakeIAKTPM{attrs: iakAttrsFor("node-07-iak", pub)}

	t.Run("a read error other than not-found is fatal", func(t *testing.T) {
		store := newFakeTPMCertStore()
		store.getErr = errors.New("object store offline")

		_, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Contains(t, err.Error(), "object store offline")
	})

	t.Run("a write error is fatal", func(t *testing.T) {
		store := newFakeTPMCertStore()
		store.certs[interimIAKCN] = cert
		store.saveErr = errors.New("disk full")

		_, err := migrateInterimIAKCertificate(tpm, store, logging.DefaultLogger())

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Contains(t, err.Error(), "disk full")
	})
}

func TestCertificateMatchesKey(t *testing.T) {
	cert, pub := selfSignedCert(t, "node-07-iak")
	_, otherPub := selfSignedCert(t, "other")

	assert.True(t, certificateMatchesKey(cert, iakAttrsFor("x", pub)))
	assert.False(t, certificateMatchesKey(cert, iakAttrsFor("x", otherPub)))
	assert.False(t, certificateMatchesKey(cert, iakAttrsFor("x", nil)), "attributes without a public key never match")
	assert.False(t, certificateMatchesKey(cert, &xkmssdk.KeyAttributes{}), "attributes without TPM attributes never match")
	assert.False(t, certificateMatchesKey(nil, iakAttrsFor("x", pub)))
}

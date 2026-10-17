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

package issuance

import (
	"context"
	"crypto"
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
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"
	caquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/ca/quicbaas"
)

// renewalKeyStore holds the leaf key or not and records the rotations a
// renewal asks for. Every other Backend method panics through the nil
// embedded interface, because a renewal must not call it — DeleteKey
// included, since a deleted name cannot be regenerated.
type renewalKeyStore struct {
	xkmsbackend.Backend
	hasKey    bool
	lookupErr error
	rotateErr error
	rotated   []string
}

func (k *renewalKeyStore) Signer(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	if k.lookupErr != nil {
		return nil, k.lookupErr
	}
	if !k.hasKey {
		return nil, caquicbaas.ErrKeyNotFound{KeyID: attrs.CN}
	}
	return nil, nil
}

func (k *renewalKeyStore) RotateKey(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if k.rotateErr != nil {
		return nil, k.rotateErr
	}
	k.rotated = append(k.rotated, attrs.CN)
	return nil, nil
}

// renewalCertStore records the certificates a renewal removes.
type renewalCertStore struct {
	certstore.CertStore
	deleteErr error
	deleted   []string
}

func (s *renewalCertStore) DeleteCertificate(id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, id)
	return nil
}

// renewalCA records the revocations a renewal performs.
type renewalCA struct {
	root, intermediate *x509.Certificate
	keyStore           xkmsbackend.Backend
	certStore          certstore.CertStore
	revokeErr          error
	revocations        []quicbaasca.RevokeOptions
}

func (c *renewalCA) TrustedRoot() (*x509.Certificate, error)         { return c.root, nil }
func (c *renewalCA) TrustedIntermediate() (*x509.Certificate, error) { return c.intermediate, nil }
func (c *renewalCA) KeyStore() xkmsbackend.Backend                   { return c.keyStore }
func (c *renewalCA) CertStore() certstore.CertStore                  { return c.certStore }

func (c *renewalCA) RevokeCert(_ context.Context, _ *x509.Certificate, opts quicbaasca.RevokeOptions) error {
	if c.revokeErr != nil {
		return c.revokeErr
	}
	c.revocations = append(c.revocations, opts)
	return nil
}

type renewalFixture struct {
	ca        *renewalCA
	keys      *renewalKeyStore
	certStore *renewalCertStore
	leaf      *x509.Certificate
}

func newRenewalFixture(t *testing.T) *renewalFixture {
	t.Helper()
	keys := &renewalKeyStore{hasKey: true}
	certStore := &renewalCertStore{}
	return &renewalFixture{
		ca: &renewalCA{
			root:         selfSigned(t, "root-ca"),
			intermediate: selfSigned(t, "intermediate-ca"),
			keyStore:     keys,
			certStore:    certStore,
		},
		keys:      keys,
		certStore: certStore,
		leaf:      selfSigned(t, "web.example.com"),
	}
}

func (f *renewalFixture) supersede() error {
	attrs := &xkmssdk.KeyAttributes{CN: f.leaf.Subject.CommonName, KeyType: xkmssdk.KeyTypeTLS}
	return SupersedeForRenewal(context.Background(), f.ca, f.leaf, attrs)
}

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestSupersedeForRenewal_RotatesTheKeyThenRevokesAndRemoves(t *testing.T) {
	t.Parallel()
	f := newRenewalFixture(t)
	cn := f.leaf.Subject.CommonName

	if err := f.supersede(); err != nil {
		t.Fatalf("SupersedeForRenewal: %v", err)
	}
	if len(f.keys.rotated) != 1 || f.keys.rotated[0] != cn {
		t.Errorf("rotated keys = %v, want exactly [%s]", f.keys.rotated, cn)
	}
	if len(f.ca.revocations) != 1 || f.ca.revocations[0].DeleteKeys {
		t.Errorf("revocations = %+v, want one that keeps the rotated key", f.ca.revocations)
	}
	if len(f.certStore.deleted) != 1 || f.certStore.deleted[0] != cn {
		t.Errorf("removed certificates = %v, want exactly [%s]", f.certStore.deleted, cn)
	}
}

func TestSupersedeForRenewal_LeafWithoutAKeystoreKeyIsNotRotated(t *testing.T) {
	t.Parallel()
	f := newRenewalFixture(t)
	f.keys.hasKey = false

	if err := f.supersede(); err != nil {
		t.Fatalf("SupersedeForRenewal: %v", err)
	}
	if len(f.keys.rotated) != 0 {
		t.Errorf("rotated %v for a leaf whose key the CA does not hold", f.keys.rotated)
	}
	if len(f.ca.revocations) != 1 || len(f.certStore.deleted) != 1 {
		t.Error("the old certificate must still be revoked and removed")
	}
}

func TestSupersedeForRenewal_RotationFailureLeavesTheCertificate(t *testing.T) {
	t.Parallel()
	f := newRenewalFixture(t)
	rotateErr := errors.New("kms unavailable")
	f.keys.rotateErr = rotateErr

	err := f.supersede()
	var typed *RenewKeyRotationError
	if !errors.As(err, &typed) || !errors.Is(err, rotateErr) {
		t.Fatalf("err = %v, want RenewKeyRotationError wrapping the KMS failure", err)
	}
	if IsRenewalRefused(err) {
		t.Error("a KMS failure is a server failure, not a refused renewal")
	}
	if len(f.ca.revocations) != 0 || len(f.certStore.deleted) != 0 {
		t.Error("a failed rotation must leave the old certificate in place")
	}
}

func TestSupersedeForRenewal_KeyLookupFailureIsTyped(t *testing.T) {
	t.Parallel()
	f := newRenewalFixture(t)
	lookupErr := errors.New("transport closed")
	f.keys.lookupErr = lookupErr

	err := f.supersede()
	var typed *RenewKeyRotationError
	if !errors.As(err, &typed) || !errors.Is(err, lookupErr) {
		t.Fatalf("err = %v, want RenewKeyRotationError wrapping the lookup failure", err)
	}
	if len(f.keys.rotated) != 0 || len(f.ca.revocations) != 0 {
		t.Error("a failed key lookup must neither rotate nor revoke")
	}
}

func TestSupersedeForRenewal_RevocationFailureIsTyped(t *testing.T) {
	t.Parallel()
	f := newRenewalFixture(t)
	revokeErr := errors.New("crl write failed")
	f.ca.revokeErr = revokeErr

	err := f.supersede()
	var typed *RenewSupersedeError
	if !errors.As(err, &typed) || !errors.Is(err, revokeErr) {
		t.Fatalf("err = %v, want RenewSupersedeError wrapping the revocation failure", err)
	}
	if len(f.certStore.deleted) != 0 {
		t.Error("a failed revocation must not remove the certificate")
	}
}

func TestSupersedeForRenewal_CertificateRemovalFailureIsTyped(t *testing.T) {
	t.Parallel()
	f := newRenewalFixture(t)
	deleteErr := errors.New("object store read-only")
	f.certStore.deleteErr = deleteErr

	err := f.supersede()
	var typed *RenewSupersedeError
	if !errors.As(err, &typed) || !errors.Is(err, deleteErr) {
		t.Fatalf("err = %v, want RenewSupersedeError wrapping the store failure", err)
	}
}

func TestSupersedeForRenewal_RefusesTheCAOwnCertificates(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"root", "intermediate"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newRenewalFixture(t)
			f.leaf = f.ca.root
			if name == "intermediate" {
				f.leaf = f.ca.intermediate
			}

			err := f.supersede()
			var typed *RenewCAOwnCertificateError
			if !errors.As(err, &typed) || !IsRenewalRefused(err) {
				t.Fatalf("err = %v, want a refused RenewCAOwnCertificateError", err)
			}
			if len(f.keys.rotated) != 0 || len(f.ca.revocations) != 0 {
				t.Error("renewal touched the CA signing key or revoked the CA certificate")
			}
		})
	}
}

func TestSupersedeForRenewal_RefusesWithoutTheStoresItChanges(t *testing.T) {
	t.Parallel()
	t.Run("keystore", func(t *testing.T) {
		t.Parallel()
		f := newRenewalFixture(t)
		f.ca.keyStore = nil
		assertStoreUnavailable(t, f, "keystore")
	})
	t.Run("certificate store", func(t *testing.T) {
		t.Parallel()
		f := newRenewalFixture(t)
		f.ca.certStore = nil
		assertStoreUnavailable(t, f, "certificate store")
	})
}

func assertStoreUnavailable(t *testing.T, f *renewalFixture, store string) {
	t.Helper()
	err := f.supersede()
	var typed *RenewStoreUnavailableError
	if !errors.As(err, &typed) || typed.Store != store || !IsRenewalRefused(err) {
		t.Fatalf("err = %v, want a refused RenewStoreUnavailableError for the %s", err, store)
	}
	if len(f.keys.rotated) != 0 || len(f.ca.revocations) != 0 {
		t.Error("renewal changed the CA without both stores")
	}
}

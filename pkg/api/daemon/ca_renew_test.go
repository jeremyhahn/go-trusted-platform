package daemon

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	caquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/ca/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
)

// renewKeyStore is the CA keystore a renewal sees: it holds the leaf key or
// not, and records the rotations and deletions the renewal asks for. Every
// other Backend method panics through the nil embedded interface, because a
// renewal must not call it.
type renewKeyStore struct {
	xkmssdk.ServiceBackend
	hasKey    bool
	lookupErr error
	rotateErr error
	rotated   []string
	deleted   []string
}

func (k *renewKeyStore) Signer(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	if k.lookupErr != nil {
		return nil, k.lookupErr
	}
	if !k.hasKey {
		return nil, caquicbaas.ErrKeyNotFound{KeyID: attrs.CN}
	}
	return nil, nil
}

func (k *renewKeyStore) RotateKey(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if k.rotateErr != nil {
		return nil, k.rotateErr
	}
	k.rotated = append(k.rotated, attrs.CN)
	return nil, nil
}

func (k *renewKeyStore) DeleteKey(_ context.Context, attrs *xkmssdk.KeyAttributes) error {
	k.deleted = append(k.deleted, attrs.CN)
	return nil
}

// renewCertStore records the certificates a renewal removes and can fail the
// removal.
type renewCertStore struct {
	*mockCertStore
	deleteErr error
	deleted   []string
}

func (s *renewCertStore) DeleteCertificate(id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, id)
	return nil
}

// renewRecordingCA records the revocations and issuances a renewal performs.
type renewRecordingCA struct {
	configurableMockCA
	revocations []xkmsca.RevokeOptions
	issued      []*xkmsca.CACertificateRequest
}

func (m *renewRecordingCA) RevokeCert(ctx context.Context, cert *x509.Certificate, opts xkmsca.RevokeOptions) error {
	m.revocations = append(m.revocations, opts)
	return m.configurableMockCA.RevokeCert(ctx, cert, opts)
}

func (m *renewRecordingCA) IssueCertificate(ctx context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	m.issued = append(m.issued, req)
	return m.configurableMockCA.IssueCertificate(ctx, req)
}

type renewFixture struct {
	svc       *CAGRPCService
	ca        *renewRecordingCA
	certStore *renewCertStore
	existing  *x509.Certificate
	serial    string
}

func newRenewFixture(t *testing.T, keys *renewKeyStore) *renewFixture {
	t.Helper()
	existing := createTestCertificate(t)
	serial := hex.EncodeToString(existing.SerialNumber.Bytes())
	certStore := &renewCertStore{mockCertStore: &mockCertStore{
		certs: map[string]*x509.Certificate{serial: existing},
	}}
	ca := &renewRecordingCA{configurableMockCA: configurableMockCA{
		certStore:  certStore,
		issuedCert: createTestCertificate(t),
	}}
	if keys != nil {
		ca.keyStore = keys
	}
	return &renewFixture{
		svc:       &CAGRPCService{ca: ca},
		ca:        ca,
		certStore: certStore,
		existing:  existing,
		serial:    serial,
	}
}

func (f *renewFixture) renew() (*platformv1.RenewCertificateResponse, error) {
	return f.svc.RenewCertificate(context.Background(), &platformv1.RenewCertificateRequest{
		Serial:    f.serial,
		ValidDays: 90,
	})
}

func TestCAGRPCService_RenewCertificate_RotatesTheLeafKey(t *testing.T) {
	t.Parallel()
	keys := &renewKeyStore{hasKey: true}
	f := newRenewFixture(t, keys)
	cn := f.existing.Subject.CommonName

	resp, err := f.renew()
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if resp.GetNewCertificate() == nil {
		t.Fatal("expected the renewed certificate in the response")
	}
	if len(keys.rotated) != 1 || keys.rotated[0] != cn {
		t.Errorf("rotated keys = %v, want exactly [%s]", keys.rotated, cn)
	}
	if len(keys.deleted) != 0 {
		t.Errorf("renewal deleted keys %v: a deleted name cannot be regenerated", keys.deleted)
	}
	if len(f.ca.revocations) != 1 || f.ca.revocations[0].DeleteKeys {
		t.Errorf("revocations = %+v, want one revocation that keeps the rotated key", f.ca.revocations)
	}
	if len(f.certStore.deleted) != 1 || f.certStore.deleted[0] != cn {
		t.Errorf("removed certificates = %v, want exactly [%s]", f.certStore.deleted, cn)
	}
	if len(f.ca.issued) != 1 || f.ca.issued[0].KeyAttributes.CN != cn {
		t.Fatalf("issued = %d requests, want one for %s", len(f.ca.issued), cn)
	}
}

func TestCAGRPCService_RenewCertificate_LeafWithoutKeystoreKeyIsReissued(t *testing.T) {
	t.Parallel()
	keys := &renewKeyStore{hasKey: false}
	f := newRenewFixture(t, keys)

	if _, err := f.renew(); err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if len(keys.rotated) != 0 {
		t.Errorf("rotated %v for a leaf whose key the CA does not hold", keys.rotated)
	}
	if len(f.ca.issued) != 1 {
		t.Errorf("issued = %d requests, want 1", len(f.ca.issued))
	}
}

func TestCAGRPCService_RenewCertificate_RotationFailureIsInternal(t *testing.T) {
	t.Parallel()
	f := newRenewFixture(t, &renewKeyStore{hasKey: true, rotateErr: errors.New("kms unavailable")})

	resp, err := f.renew()
	if resp != nil {
		t.Error("expected no response")
	}
	assertGRPCError(t, err, codes.Internal)
	if !strings.Contains(err.Error(), "kms unavailable") {
		t.Errorf("err = %v, want the KMS failure in the status message", err)
	}
	if len(f.ca.revocations) != 0 || len(f.certStore.deleted) != 0 || len(f.ca.issued) != 0 {
		t.Error("a failed rotation must leave the old certificate in place")
	}
}

func TestCAGRPCService_RenewCertificate_RefusesTheCAOwnCertificate(t *testing.T) {
	t.Parallel()
	keys := &renewKeyStore{hasKey: true}
	f := newRenewFixture(t, keys)
	f.ca.trustedRoot = f.existing

	_, err := f.renew()
	assertGRPCError(t, err, codes.FailedPrecondition)
	if len(keys.rotated) != 0 || len(f.ca.revocations) != 0 || len(f.ca.issued) != 0 {
		t.Error("renewal touched the CA signing key or revoked the CA certificate")
	}
}

func TestCAGRPCService_RenewCertificate_NoKeyStoreIsFailedPrecondition(t *testing.T) {
	t.Parallel()
	f := newRenewFixture(t, nil)

	_, err := f.renew()
	assertGRPCError(t, err, codes.FailedPrecondition)
	if len(f.ca.revocations) != 0 || len(f.ca.issued) != 0 {
		t.Error("renewal revoked or issued without a keystore to rotate the key in")
	}
}

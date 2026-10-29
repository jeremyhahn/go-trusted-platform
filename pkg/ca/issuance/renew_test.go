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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// renewKeyStore records the keys a renewal rotates.
type renewKeyStore struct {
	xkmsbackend.Backend
	rotated   []*xkmssdk.KeyAttributes
	rotateErr error
}

func (k *renewKeyStore) RotateKey(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	if k.rotateErr != nil {
		return nil, k.rotateErr
	}
	k.rotated = append(k.rotated, attrs)
	return nil, nil
}

// renewCertStore records the certificates a renewal removes.
type renewCertStore struct {
	xkmssdk.CertStore
	deleted []string
}

func (s *renewCertStore) DeleteCertificate(cn string) error {
	s.deleted = append(s.deleted, cn)
	return nil
}

// renewCA is the CA surface a renewal reaches; the steps record what they saw.
type renewCA struct {
	quicbaasca.CACertificateAuthority
	keyStore    *renewKeyStore
	certStore   *renewCertStore
	revokeOpts  []quicbaasca.RevokeOptions
	issued      []*quicbaasca.CACertificateRequest
	issueErr    error
	renewedCert *x509.Certificate
}

func newRenewCA() *renewCA {
	return &renewCA{
		keyStore:    &renewKeyStore{},
		certStore:   &renewCertStore{},
		renewedCert: &x509.Certificate{SerialNumber: big.NewInt(2)},
	}
}

func (c *renewCA) KeyStore() xkmsbackend.Backend {
	if c.keyStore == nil {
		return nil
	}
	return c.keyStore
}

func (c *renewCA) CertStore() xkmssdk.CertStore {
	if c.certStore == nil {
		return nil
	}
	return c.certStore
}

func (c *renewCA) RevokeCert(_ context.Context, _ *x509.Certificate, opts quicbaasca.RevokeOptions) error {
	c.revokeOpts = append(c.revokeOpts, opts)
	return nil
}

func (c *renewCA) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	c.issued = append(c.issued, req)
	if c.issueErr != nil {
		return nil, c.issueErr
	}
	return &quicbaasca.IssuedCertificate{Certificate: c.renewedCert}, nil
}

func renewableCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "svc.example.com", Organization: []string{"Example"}},
		PublicKeyAlgorithm: x509.ECDSA,
		DNSNames:           []string{"svc.example.com"},
		IPAddresses:        []net.IP{net.ParseIP("192.0.2.10")},
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}
}

// Renewal re-keys under the same name (docs/ca/user.md "Renewing"): revoke
// without deleting the key, rotate it, remove the old certificate, issue.
func TestRenew_RotatesTheKeyAndIssuesOnIt(t *testing.T) {
	ca := newRenewCA()
	existing := renewableCert()

	renewed, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 90, PreserveSANs: true})

	require.NoError(t, err)
	assert.Same(t, ca.renewedCert, renewed)
	require.Len(t, ca.revokeOpts, 1)
	assert.False(t, ca.revokeOpts[0].DeleteKeys, "a renewal keeps its key's name")
	require.Len(t, ca.keyStore.rotated, 1)
	assert.Equal(t, "svc.example.com", ca.keyStore.rotated[0].CN)
	assert.Equal(t, x509.ECDSA, ca.keyStore.rotated[0].KeyAlgorithm)
	assert.Equal(t, []string{"svc.example.com"}, ca.certStore.deleted)

	require.Len(t, ca.issued, 1)
	req := ca.issued[0]
	assert.Equal(t, 90, req.Valid)
	assert.Equal(t, "svc.example.com", req.Subject.CommonName)
	assert.Equal(t, "Example", req.Subject.Organization)
	assert.Equal(t, x509.KeyUsageDigitalSignature, req.KeyUsage)
	require.NotNil(t, req.SANS)
	assert.Equal(t, []string{"svc.example.com"}, req.SANS.DNS)
	assert.Equal(t, []string{"192.0.2.10"}, req.SANS.IPs)
	assert.Equal(t, xkmssdk.StoreSoftware, req.KeyAttributes.StoreType)
}

func TestRenew_NewSANsReplaceTheOldOnesAndNoFlagDropsThem(t *testing.T) {
	ca := newRenewCA()
	newSANs := &quicbaasca.CASubjectAlternativeNames{DNS: []string{"new.example.com"}}

	_, err := Renew(context.Background(), ca, renewableCert(), RenewOptions{ValidDays: 30, PreserveSANs: true, NewSANs: newSANs})
	require.NoError(t, err)
	_, err = Renew(context.Background(), ca, renewableCert(), RenewOptions{ValidDays: 30})
	require.NoError(t, err)

	require.Len(t, ca.issued, 2)
	assert.Same(t, newSANs, ca.issued[0].SANS)
	assert.Nil(t, ca.issued[1].SANS)
}

func TestRenew_RefusesACAWithoutItsStores(t *testing.T) {
	ca := newRenewCA()
	ca.keyStore = nil

	_, err := Renew(context.Background(), ca, renewableCert(), RenewOptions{ValidDays: 30})

	var storesErr *RenewStoresUnavailableError
	require.ErrorAs(t, err, &storesErr)
	assert.Empty(t, ca.revokeOpts, "nothing is revoked when the renewal cannot finish")
}

func TestRenew_AFailedRotationIssuesNothing(t *testing.T) {
	ca := newRenewCA()
	ca.keyStore.rotateErr = errors.New("rotation refused")

	_, err := Renew(context.Background(), ca, renewableCert(), RenewOptions{ValidDays: 30})

	var renewErr *RenewError
	require.ErrorAs(t, err, &renewErr)
	assert.Equal(t, "rotate the key", renewErr.Step)
	assert.ErrorIs(t, err, ca.keyStore.rotateErr)
	assert.Empty(t, ca.issued)
}

func TestRenew_AFailedIssueIsARenewError(t *testing.T) {
	ca := newRenewCA()
	ca.issueErr = errors.New("issuer down")

	_, err := Renew(context.Background(), ca, renewableCert(), RenewOptions{ValidDays: 30})

	var renewErr *RenewError
	require.ErrorAs(t, err, &renewErr)
	assert.Equal(t, "issue the renewed certificate", renewErr.Step)
	assert.EqualError(t, err, "failed to issue the renewed certificate: issuer down")
}

// TestRenew_AnRSALeafRenewsOnARealSoftwareCA issues an RSA leaf on a
// software-backed go-xkms CA and renews it. The software backend validates the
// rotation's key attributes, so attributes without the RSA key size fail the
// renewal after the old certificate is already revoked (Codex 8270 P1).
func TestRenew_AnRSALeafRenewsOnARealSoftwareCA(t *testing.T) {
	root := newRenewableRootCA(t)
	issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{CommonName: "renew-rsa.test", Organization: "Test Org", Country: "US"},
		Valid:   1,
		KeyAttributes: &xkmssdk.KeyAttributes{
			CN:            "renew-rsa.test",
			KeyAlgorithm:  x509.RSA,
			RSAAttributes: &xkmssdk.RSAAttributes{KeySize: 2048},
			StoreType:     xkmssdk.StoreSoftware,
			KeyType:       xkmssdk.KeyTypeTLS,
		},
	})
	require.NoError(t, err)
	issuedKey, ok := issued.Certificate.PublicKey.(*rsa.PublicKey)
	require.True(t, ok, "the issued leaf must carry an RSA key")

	renewed, err := Renew(context.Background(), root, issued.Certificate, RenewOptions{ValidDays: 1})
	require.NoError(t, err)
	require.NotNil(t, renewed)

	renewedKey, ok := renewed.PublicKey.(*rsa.PublicKey)
	require.True(t, ok, "the renewed certificate must carry an RSA key")
	assert.Equal(t, issuedKey.N.BitLen(), renewedKey.N.BitLen(), "renewal must keep the RSA key size")
	assert.NotEqual(t, 0, issued.Certificate.SerialNumber.Cmp(renewed.SerialNumber), "renewal must issue a new serial")
}

func TestRenewalKeyAttributes_RSACarriesTheModulusSize(t *testing.T) {
	modulus := new(big.Int).Lsh(big.NewInt(1), 3071)
	existing := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "rsa.test"},
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &rsa.PublicKey{N: modulus, E: 65537},
	}

	attrs := renewalKeyAttributes(existing)

	require.NotNil(t, attrs.RSAAttributes, "an RSA certificate must yield RSA attributes")
	assert.Equal(t, 3072, attrs.RSAAttributes.KeySize)
	assert.Nil(t, attrs.ECCAttributes, "an RSA certificate must not yield ECC attributes")
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
}

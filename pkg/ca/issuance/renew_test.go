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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// renewIssuerCA is a renewCA whose own certificate is issuer, so a CA
// certificate's renewal reaches the issuer checks.
type renewIssuerCA struct {
	*renewCA
	issuer *x509.Certificate
	bundle []byte
}

func (c *renewIssuerCA) CACertificate() (*x509.Certificate, error) {
	return c.issuer, nil
}

func (c *renewIssuerCA) CABundle() ([]byte, error) { return c.bundle, nil }

func renewableCACert(maxPathLen int) *x509.Certificate {
	existing := renewableCert()
	existing.IsCA = true
	existing.BasicConstraintsValid = true
	existing.MaxPathLen = maxPathLen
	existing.MaxPathLenZero = maxPathLen == 0
	// The SDK's CA profile writes this mask; any other is refused on renewal.
	existing.KeyUsage = caProfileKeyUsage
	return existing
}

// assertRenewalUntouched checks that a refused renewal revoked, rotated,
// deleted and issued nothing (Codex 8615 P1).
func assertRenewalUntouched(t *testing.T, ca *renewCA) {
	t.Helper()
	assert.Empty(t, ca.revokeOpts, "a refused renewal must not revoke the old certificate")
	assert.Empty(t, ca.keyStore.rotated, "a refused renewal must not rotate the key")
	assert.Empty(t, ca.certStore.deleted, "a refused renewal must keep the stored certificate")
	assert.Empty(t, ca.issued, "a refused renewal must issue nothing")
}

func TestRenew_APathLenRefusalLeavesTheOldCertificate(t *testing.T) {
	ca := &renewIssuerCA{
		renewCA: newRenewCA(),
		issuer: &x509.Certificate{
			Subject:               pkix.Name{CommonName: "Tight Issuer"},
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            1,
		},
	}

	_, err := Renew(context.Background(), ca, renewableCACert(1), RenewOptions{ValidDays: 30})

	var renewErr *RenewError
	require.ErrorAs(t, err, &renewErr)
	assert.Equal(t, "check the renewal against the issuer", renewErr.Step)
	var exceeded *SubordinatePathLenError
	require.ErrorAs(t, err, &exceeded)
	assert.Equal(t, 1, exceeded.Requested)
	assert.Equal(t, 0, exceeded.Allowed)
	assert.True(t, IsInvalidRequest(err))
	assertRenewalUntouched(t, ca.renewCA)
}

// A path length above the issuing CA refuses a CA certificate's renewal like
// the issuing CA's own, before anything is revoked (Codex round 3 on #1544).
func TestRenew_AnInheritedPathLenRefusalLeavesTheOldCertificate(t *testing.T) {
	certs, _ := newCAChain(t, 1, -1)
	ca := &renewIssuerCA{
		renewCA: newRenewCA(),
		issuer:  certs[1],
		bundle:  pemBundle(certs[1], certs[0]),
	}

	_, err := Renew(context.Background(), ca, renewableCACert(0), RenewOptions{ValidDays: 30})

	var renewErr *RenewError
	require.ErrorAs(t, err, &renewErr)
	assert.Equal(t, "check the renewal against the issuer", renewErr.Step)
	assert.True(t, IsInvalidRequest(err))
	assert.ErrorContains(t, err, "inherit-ca-0")
	assertRenewalUntouched(t, ca.renewCA)
}

func TestRenew_AnEKURestrictedCAIsRefusedBeforeRevocation(t *testing.T) {
	ca := &renewIssuerCA{
		renewCA: newRenewCA(),
		issuer:  &x509.Certificate{Subject: pkix.Name{CommonName: "Root"}, IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1},
	}
	existing := renewableCACert(0)
	existing.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	assert.ErrorIs(t, err, ErrCAExtKeyUsageUnsupported{})
	assert.True(t, IsInvalidRequest(err))
	assertRenewalUntouched(t, ca.renewCA)
}

// encodedCACert signs the CA template with a fresh key and parses the result,
// so the restriction under test is the one a stored certificate's extensions
// actually carry, not a field set on an in-memory struct.
func encodedCACert(t *testing.T, restrict func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := renewableCACert(0)
	restrict(template)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestRenew_ACAWithARestrictionTheSDKCannotCarryIsRefusedBeforeRevocation(t *testing.T) {
	cases := map[string]struct {
		restrict    func(*x509.Certificate)
		restriction string
	}{
		"permitted DNS domain": {
			restrict:    func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"example.com"} },
			restriction: "name constraints",
		},
		"excluded URI domain": {
			restrict:    func(c *x509.Certificate) { c.ExcludedURIDomains = []string{"evil.example"} },
			restriction: "name constraints",
		},
		"only an unknown EKU OID": {
			restrict: func(c *x509.Certificate) {
				c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}
			},
			restriction: "an unrecognized extended key usage",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ca := &renewIssuerCA{
				renewCA: newRenewCA(),
				issuer:  &x509.Certificate{Subject: pkix.Name{CommonName: "Root"}, IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1},
			}
			existing := encodedCACert(t, tc.restrict)

			_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

			var refusal *CARestrictionUnsupportedError
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, tc.restriction, refusal.Restriction)
			assert.True(t, IsInvalidRequest(err))
			assert.Contains(t, err.Error(), "ca.CertificateRequest", "the refusal names the SDK gap")
			assertRenewalUntouched(t, ca.renewCA)
		})
	}
}

// The SDK's CA profile replaces the request's KeyUsage with its own mask, so
// renewing a CA restricted to keyCertSign alone would grant it cRLSign and
// digitalSignature. The renewal is refused before anything is revoked.
func TestRenew_ACAWithOnlyKeyCertSignIsRefusedBeforeRevocation(t *testing.T) {
	ca := &renewIssuerCA{
		renewCA: newRenewCA(),
		issuer:  &x509.Certificate{Subject: pkix.Name{CommonName: "Root"}, IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1},
	}
	existing := encodedCACert(t, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign })
	require.Equal(t, x509.KeyUsageCertSign, existing.KeyUsage)

	_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	var refusal *CAKeyUsageUnsupportedError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, x509.KeyUsageCertSign, refusal.Requested)
	assert.Equal(t, caProfileKeyUsage, refusal.Profile)
	assert.True(t, IsInvalidRequest(err))
	assert.Contains(t, err.Error(), "ca.NewCAProfile", "the refusal names the SDK gap")
	assertRenewalUntouched(t, ca.renewCA)
}

func TestCheckRenewableRestrictions_ALeafAndAnUnrestrictedCAPass(t *testing.T) {
	assert.NoError(t, checkRenewableRestrictions(nil))
	assert.NoError(t, checkRenewableRestrictions(renewableCert()))
	assert.NoError(t, checkRenewableRestrictions(encodedCACert(t, func(*x509.Certificate) {})))
}

// encodedLeafCert encodes a client certificate with the usages ParseRequestUsages
// returns for extKeyUsageNames, as Issue would sign it, and parses it back.
func encodedLeafCert(t *testing.T, extKeyUsageNames []string) *x509.Certificate {
	t.Helper()
	keyUsage, extKeyUsage, extensions, err := ParseRequestUsages(false, []string{"DIGITAL_SIGNATURE"}, extKeyUsageNames)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := renewableCert()
	template.KeyUsage = keyUsage
	template.ExtKeyUsage = extKeyUsage
	template.ExtraExtensions = extensions
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// The renewal request cannot carry the tp-pxeInstaller marker, so renewing an
// installer certificate would issue an unrestricted client certificate
// (Codex 8676). The renewal is refused before anything is revoked, rotated or
// issued: the next PXE install issues a new installer certificate.
func TestRenew_AnInstallerCertificateIsRefusedBeforeRevocation(t *testing.T) {
	ca := newRenewCA()
	existing := encodedLeafCert(t, []string{"PXE_INSTALLER"})
	require.True(t, HasInstallerMarker(existing), "the test certificate carries the installer marker")
	require.Empty(t, existing.UnhandledCriticalExtensions, "Go processes the marker's EKU extension")

	_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	require.ErrorIs(t, err, ErrInstallerRenewal{})
	assert.True(t, IsInvalidRequest(err))
	assert.Contains(t, err.Error(), "not renewable")
	assertRenewalUntouched(t, ca)
}

// A client certificate without the marker still renews: the refusal is keyed
// on the marker, not on id-kp-clientAuth.
func TestRenew_AClientAuthLeafWithoutTheMarkerRenews(t *testing.T) {
	ca := newRenewCA()
	existing := encodedLeafCert(t, []string{"CLIENT_AUTH"})
	require.False(t, HasInstallerMarker(existing))

	renewed, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	require.NoError(t, err)
	assert.Same(t, ca.renewedCert, renewed)
	require.Len(t, ca.revokeOpts, 1)
	require.Len(t, ca.issued, 1)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca.issued[0].ExtKeyUsage)
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

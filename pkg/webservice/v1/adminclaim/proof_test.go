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

package adminclaim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTrustAnchor(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()

	valid := filepath.Join(dir, "ca-chain.crt")
	require.NoError(t, os.WriteFile(valid,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.rootCert.Raw}), 0o600))

	pool, err := LoadTrustAnchor(valid)
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestLoadTrustAnchor_Failures(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "garbage.crt")
	require.NoError(t, os.WriteFile(notPEM, []byte("this is not a certificate"), 0o600))

	tests := []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(dir, "absent.crt")},
		{"not a certificate", notPEM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := LoadTrustAnchor(tt.path)
			assert.Nil(t, pool)
			var unreadable ErrAnchorUnreadable
			require.ErrorAs(t, err, &unreadable)
			assert.Equal(t, tt.path, unreadable.Path)
		})
	}
}

func TestParseCertificatePEM_Failures(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong block type", string(pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))},
		{"unparseable DER", string(pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseCertificatePEM([]byte(tt.in))
			assert.Nil(t, cert)
			require.ErrorAs(t, err, &ErrCertificateInvalid{})
		})
	}
}

func TestVerifyAdminCertificate_NoAnchorDenies(t *testing.T) {
	p := newPKI(t)
	cert, _, _ := p.adminLeaf(t)
	err := verifyAdminCertificate(cert, nil, "admin", testTenantID)
	require.ErrorAs(t, err, &ErrCertificateInvalid{})
}

func TestVerifyAdminCertificate_RejectsServerAuthOnlyLeaf(t *testing.T) {
	p := newPKI(t)
	cert, _, _ := p.issue(t, leafOptions{
		commonName: "admin",
		extKeyUsse: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	err := verifyAdminCertificate(cert, p.pool, "admin", testTenantID)
	require.ErrorAs(t, err, &ErrCertificateInvalid{})
}

// TestVerifyAdminCertificate_SPIFFEIdentityIsMandatory keeps the bootstrap
// credential class to the one identity firstboot issues. A ClientAuth
// certificate the anchor happened to issue with CN=admin is not it.
func TestVerifyAdminCertificate_SPIFFEIdentityIsMandatory(t *testing.T) {
	p := newPKI(t)
	tests := []struct {
		name      string
		spiffeURI string
		ok        bool
	}{
		{"canonical firstboot id", "spiffe://tp.internal/tenant/system/user/admin", true},
		{"trailing slash", "spiffe://tp.internal/tenant/system/user/admin/", true},
		{"uppercase scheme", "SPIFFE://tp.internal/tenant/system/user/admin", true},

		{"no URI SAN at all", "", false},
		{"names another user", "spiffe://tp.internal/tenant/system/user/mallory", false},
		{"ANOTHER TENANT'S admin", "spiffe://tp.internal/tenant/acme/user/admin", false},
		{"empty tenant segment", "spiffe://tp.internal/tenant//user/admin", false},
		{"wrong path shape", "spiffe://tp.internal/user/admin", false},
		{"extra segments", "spiffe://tp.internal/tenant/system/user/admin/extra", false},
		{"suffix smuggled into the tenant", "spiffe://tp.internal/tenant/x%2Fuser%2Fadmin/user/bob", false},
		{"not a spiffe scheme", "https://tp.internal/tenant/system/user/admin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _, _ := p.issue(t, leafOptions{
				commonName: "admin", spiffeURI: tt.spiffeURI,
			})
			err := verifyAdminCertificate(cert, p.pool, "admin", testTenantID)
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorAs(t, err, &ErrIdentityMismatch{})
		})
	}
}

func TestIsAdminSPIFFEID_NilURI(t *testing.T) {
	assert.False(t, isAdminSPIFFEID(nil, "admin", testTenantID))
}

func TestVerifyChallengeSignature_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := selfSigned(t, key, &key.PublicKey)

	challenge := []byte("nonce")
	digest := sha256.Sum256(challenge)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	require.NoError(t, verifyChallengeSignature(cert, challenge, sig))
	require.ErrorAs(t, verifyChallengeSignature(cert, []byte("other"), sig), &ErrProofInvalid{})
}

func TestVerifyChallengeSignature_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cert := selfSigned(t, priv, pub)

	challenge := []byte("nonce")
	sig := ed25519.Sign(priv, challenge)

	require.NoError(t, verifyChallengeSignature(cert, challenge, sig))
	require.ErrorAs(t, verifyChallengeSignature(cert, []byte("other"), sig), &ErrProofInvalid{})
}

func TestVerifyChallengeSignature_UnsupportedKeyIsRefused(t *testing.T) {
	p := newPKI(t)
	cert, _, _ := p.adminLeaf(t)
	// Swap in a key type the verifier does not know about.
	cert.PublicKey = struct{}{}
	err := verifyChallengeSignature(cert, []byte("nonce"), []byte("sig"))
	require.ErrorAs(t, err, &ErrProofInvalid{})
}

func TestVerifyChallengeSignature_EmptySignature(t *testing.T) {
	p := newPKI(t)
	cert, _, _ := p.adminLeaf(t)
	require.ErrorAs(t, verifyChallengeSignature(cert, []byte("n"), nil), &ErrProofInvalid{})
}

// selfSigned mints a throwaway self-signed certificate for a key whose
// only job is to carry a public key into the signature verifier.
func selfSigned(t *testing.T, signer crypto.Signer, pub any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestTypedErrors exercises the message and unwrap surface so a change to
// an error string is a deliberate act, not a silent one.
func TestTypedErrors(t *testing.T) {
	cause := errors.New("boom")
	tests := []struct {
		name     string
		err      error
		contains string
		unwraps  bool
	}{
		{"dependency", ErrDependencyRequired{Name: "logger"}, "logger is required", false},
		{"body", ErrInvalidRequestBody{Cause: cause}, "invalid request body", true},
		{"challenge", ErrChallengeUnknown{}, "spent or expired", false},
		{"cert with cause", ErrCertificateInvalid{Reason: "r", Cause: cause}, "boom", true},
		{"cert without cause", ErrCertificateInvalid{Reason: "r"}, "certificate rejected: r", false},
		{"identity", ErrIdentityMismatch{Presented: "a", Expected: "b"}, "is not the system admin", false},
		{"proof", ErrProofInvalid{Cause: cause}, "possession proof rejected", true},
		{"claim token", ErrClaimTokenInvalid{}, "claim token is missing", false},
		{"already claimed", ErrAlreadyClaimed{}, "already been claimed", false},
		{"ceremony", ErrCeremonyRejected{}, "rejected the authenticator attestation", false},
		{"anchor with cause", ErrAnchorUnreadable{Path: "p", Cause: cause}, "cannot read", true},
		{"anchor without cause", ErrAnchorUnreadable{Path: "p"}, "contains no certificate", false},
		{"capacity", ErrTooManyOutstanding{Limit: 4}, "too many outstanding", false},
		{"rejected", ErrProofRejected{}, "proof rejected", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
			if tt.unwraps {
				assert.ErrorIs(t, tt.err, cause)
			}
		})
	}
}

// TestVerifyAdminCertificate_RejectsAnotherTenantsAdmin is the regression
// for the widest hole this verifier could have: the SAME deployment CA
// also issues certificates for tenant users, so a tenant whose
// administrator happens to be named "admin" would otherwise hold a
// perfectly valid proof of the SYSTEM admin identity.
func TestVerifyAdminCertificate_RejectsAnotherTenantsAdmin(t *testing.T) {
	p := newPKI(t)
	cert, _, _ := p.issue(t, leafOptions{
		commonName: "admin",
		spiffeURI:  "spiffe://example.internal/tenant/acme/user/admin",
	})

	err := verifyAdminCertificate(cert, p.pool, "admin", "system")
	require.ErrorAs(t, err, &ErrIdentityMismatch{})

	// The same certificate IS the admin of its own tenant.
	require.NoError(t, verifyAdminCertificate(cert, p.pool, "admin", "acme"))
}

func TestVerifyAdminCertificate_UnconfiguredTenantDenies(t *testing.T) {
	p := newPKI(t)
	cert, _, _ := p.adminLeaf(t)
	require.ErrorAs(t,
		verifyAdminCertificate(cert, p.pool, "admin", ""), &ErrCertificateInvalid{})
}

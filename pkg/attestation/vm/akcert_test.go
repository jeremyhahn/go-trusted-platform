// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

var (
	akTestNow    = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	oidResidency = mustOIDFromInts(2, 23, 133, 11, 1, 1)
	oidFixed     = mustOIDFromInts(2, 23, 133, 11, 1, 2)
)

type akTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newAKTestCA(t *testing.T) *akTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             akTestNow.Add(-time.Hour),
		NotAfter:              akTestNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &akTestCA{cert: cert, key: key, pool: pool}
}

// issueAK mints an AK certificate with the given policy OIDs, signed by ca
// (or self-signed when ca is nil), valid around akTestNow unless notAfter is set.
func issueAK(t *testing.T, ca *akTestCA, policies []x509.OID, notAfter time.Time) (pemBytes []byte, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.IsZero() {
		notAfter = akTestNow.Add(12 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "tpm-ak"},
		NotBefore:    akTestNow.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:     policies,
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), &key.PublicKey
}

func TestVerifyAKCertificate_RestrictedAndChainedPasses(t *testing.T) {
	ca := newAKTestCA(t)
	certPEM, wantPub := issueAK(t, ca, []x509.OID{oidResidency, oidFixed, oidTCGVerifiedTPMRestrictedX509}, time.Time{})
	pub, err := VerifyAKCertificate(certPEM, ca.pool, nil, akTestNow)
	if err != nil {
		t.Fatalf("a chained, Restricted AK certificate must verify: %v", err)
	}
	if got, ok := pub.(*ecdsa.PublicKey); !ok || !got.Equal(wantPub) {
		t.Fatal("returned public key is not the certified key")
	}
}

// TestVerifyAKCertificate_MissingRestrictedIsRefused is the spec's MUST
// (TCG DevID v1 r12 §8.2): a certificate that chains perfectly but carries
// only residency+fixed — the exact set every AK cert carried before
// go-xkms#358 — is not an attestation-key certificate a relying party may
// trust.
func TestVerifyAKCertificate_MissingRestrictedIsRefused(t *testing.T) {
	ca := newAKTestCA(t)
	certPEM, _ := issueAK(t, ca, []x509.OID{oidResidency, oidFixed}, time.Time{})
	_, err := VerifyAKCertificate(certPEM, ca.pool, nil, akTestNow)
	var notRestricted ErrAKCertificateNotRestricted
	if !errors.As(err, &notRestricted) {
		t.Fatalf("expected ErrAKCertificateNotRestricted, got %T: %v", err, err)
	}
	if notRestricted.Subject == "" {
		t.Fatal("refusal must name the certificate subject")
	}
}

func TestVerifyAKCertificate_NoPoliciesAtAllIsRefused(t *testing.T) {
	ca := newAKTestCA(t)
	certPEM, _ := issueAK(t, ca, nil, time.Time{})
	if _, err := VerifyAKCertificate(certPEM, ca.pool, nil, akTestNow); !errors.As(err, new(ErrAKCertificateNotRestricted)) {
		t.Fatalf("expected ErrAKCertificateNotRestricted, got %v", err)
	}
}

func TestVerifyAKCertificate_UntrustedIssuerIsRefused(t *testing.T) {
	trusted := newAKTestCA(t)
	rogue := newAKTestCA(t)
	certPEM, _ := issueAK(t, rogue, []x509.OID{oidTCGVerifiedTPMRestrictedX509}, time.Time{})
	_, err := VerifyAKCertificate(certPEM, trusted.pool, nil, akTestNow)
	var invalid ErrAKCertificateInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("a certificate from an untrusted CA must be ErrAKCertificateInvalid even with the attribute, got %T: %v", err, err)
	}
}

func TestVerifyAKCertificate_ExpiredIsRefused(t *testing.T) {
	ca := newAKTestCA(t)
	certPEM, _ := issueAK(t, ca, []x509.OID{oidTCGVerifiedTPMRestrictedX509}, akTestNow.Add(-time.Minute))
	if _, err := VerifyAKCertificate(certPEM, ca.pool, nil, akTestNow); !errors.As(err, new(ErrAKCertificateInvalid)) {
		t.Fatalf("expired certificate must be ErrAKCertificateInvalid, got %v", err)
	}
}

func TestVerifyAKCertificate_NilRootsSkipsChainButNotTheAttribute(t *testing.T) {
	// Self-signed, no roots supplied: chain verification is skipped, but the
	// attribute is still mandatory — nil roots must never mean "trust
	// everything".
	withAttr, _ := issueAK(t, nil, []x509.OID{oidTCGVerifiedTPMRestrictedX509}, time.Time{})
	if _, err := VerifyAKCertificate(withAttr, nil, nil, akTestNow); err != nil {
		t.Fatalf("nil roots with the attribute must pass: %v", err)
	}
	without, _ := issueAK(t, nil, []x509.OID{oidResidency}, time.Time{})
	if _, err := VerifyAKCertificate(without, nil, nil, akTestNow); !errors.As(err, new(ErrAKCertificateNotRestricted)) {
		t.Fatalf("nil roots must still require the attribute, got %v", err)
	}
}

func TestVerifyAKCertificate_GarbageIsRefused(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":       nil,
		"not pem":     []byte("hello"),
		"wrong block": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}),
		"bad der":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0xff, 0xff}}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAKCertificate(in, nil, nil, akTestNow); !errors.As(err, new(ErrAKCertificateInvalid)) {
				t.Fatalf("expected ErrAKCertificateInvalid, got %T: %v", err, err)
			}
		})
	}
}

func TestAKCertErrors_Messages(t *testing.T) {
	inner := errors.New("boom")
	e := ErrAKCertificateInvalid{Reason: "parse failed", Cause: inner}
	if e.Error() != "vm: attestation key certificate invalid: parse failed: boom" || !errors.Is(e, inner) {
		t.Errorf("unexpected: %q", e.Error())
	}
	if got := (ErrAKCertificateNotRestricted{Subject: "CN=x"}).Error(); got != `vm: attestation key certificate "CN=x" does not carry tcg-cap-verifiedTPMRestricted` {
		t.Errorf("unexpected: %q", got)
	}
}

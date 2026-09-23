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

package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI is a CA and a leaf it issued, standing in for the platform CA and
// a platform service's certificate.
type testPKI struct {
	ca   *x509.Certificate
	leaf *x509.Certificate
}

func newTestPKI(t *testing.T, cn string) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	ca := signTestCert(t, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := signTestCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "svc." + cn},
		DNSNames:     []string{"svc." + cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &leafKey.PublicKey, caKey)
	return &testPKI{ca: ca, leaf: leaf}
}

func signTestCert(t *testing.T, template, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemOf(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

func staticSource(certs ...*x509.Certificate) AnchorSource {
	return AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) { return certs, nil })
}

func TestNewAnchor_NilSource(t *testing.T) {
	if _, err := NewAnchor(nil); !errors.Is(err, ErrNilAnchorSource{}) {
		t.Fatalf("NewAnchor(nil) = %v, want ErrNilAnchorSource", err)
	}
}

// TestAnchor_CAPoolVerifiesPlatformIssuedPeers is the anchor's purpose: a
// certificate the platform CA issued verifies against the pool, and one from
// any other CA does not.
func TestAnchor_CAPoolVerifiesPlatformIssuedPeers(t *testing.T) {
	platform := newTestPKI(t, "platform.test")
	stranger := newTestPKI(t, "stranger.test")
	anchor, err := NewAnchor(staticSource(platform.ca))
	if err != nil {
		t.Fatal(err)
	}

	pool, err := anchor.CAPool(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("a platform-issued certificate must verify against the anchor: %v", err)
	}
	if _, err := stranger.leaf.Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Error("a certificate from another CA must not verify against the anchor")
	}
}

// TestAnchor_CertificatesDropsLeaves covers a bundle that carries a leaf: a
// leaf is not a trust anchor, and a source holding only leaves is empty.
func TestAnchor_CertificatesDropsLeaves(t *testing.T) {
	platform := newTestPKI(t, "platform.test")

	anchor, _ := NewAnchor(staticSource(platform.leaf, platform.ca, nil))
	certs, err := anchor.Certificates(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || !certs[0].Equal(platform.ca) {
		t.Errorf("Certificates() = %d certs, want only the CA", len(certs))
	}

	leavesOnly, _ := NewAnchor(staticSource(platform.leaf))
	if _, err := leavesOnly.CAPool(t.Context()); !errors.Is(err, ErrAnchorEmpty{}) {
		t.Errorf("CAPool() over leaves only = %v, want ErrAnchorEmpty", err)
	}
}

func TestAnchor_SourceFailureIsUnavailable(t *testing.T) {
	cause := errors.New("not enrolled")
	anchor, _ := NewAnchor(AnchorSourceFunc(func(context.Context) ([]*x509.Certificate, error) {
		return nil, cause
	}))

	_, err := anchor.TLSConfig(t.Context())
	var unavailable *ErrAnchorUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("TLSConfig() = %v, want *ErrAnchorUnavailable", err)
	}
	if !errors.Is(err, cause) {
		t.Error("ErrAnchorUnavailable must unwrap to the source's error")
	}
}

func TestAnchor_TLSConfig(t *testing.T) {
	platform := newTestPKI(t, "platform.test")
	anchor, _ := NewAnchor(staticSource(platform.ca))

	cfg, err := anchor.TLSConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("TLSConfig() must carry the anchor as RootCAs")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("TLSConfig() must verify the server")
	}
	if _, err := platform.leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs}); err != nil {
		t.Errorf("RootCAs must verify a platform-issued server: %v", err)
	}
}

// TestFileAnchorSource_ReadsOnEveryCall pins the rotation guarantee: a bundle
// replaced on disk is what the next verification uses.
func TestFileAnchorSource_ReadsOnEveryCall(t *testing.T) {
	first := newTestPKI(t, "first.test")
	rotated := newTestPKI(t, "rotated.test")
	path := filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(path, pemOf(first.ca), 0o600); err != nil {
		t.Fatal(err)
	}
	source := NewFileAnchorSource(path)
	if source.Path() != path {
		t.Errorf("Path() = %q, want %q", source.Path(), path)
	}
	anchor, _ := NewAnchor(source)

	certs, err := anchor.Certificates(t.Context())
	if err != nil || len(certs) != 1 || !certs[0].Equal(first.ca) {
		t.Fatalf("Certificates() = %v, %v; want the first CA", certs, err)
	}

	if err := os.WriteFile(path, pemOf(rotated.ca), 0o600); err != nil {
		t.Fatal(err)
	}
	certs, err = anchor.Certificates(t.Context())
	if err != nil || len(certs) != 1 || !certs[0].Equal(rotated.ca) {
		t.Fatalf("Certificates() after rotation = %v, %v; want the rotated CA", certs, err)
	}
}

func TestFileAnchorSource_Errors(t *testing.T) {
	dir := t.TempDir()

	if _, err := NewFileAnchorSource("").AnchorCertificates(t.Context()); !errors.Is(err, ErrAnchorFileUnset{}) {
		t.Errorf("unset path = %v, want ErrAnchorFileUnset", err)
	}

	var readErr *ErrCAFileRead
	if _, err := NewFileAnchorSource(filepath.Join(dir, "absent.pem")).AnchorCertificates(t.Context()); !errors.As(err, &readErr) {
		t.Errorf("missing file = %v, want *ErrCAFileRead", err)
	}

	corrupt := filepath.Join(dir, "corrupt.pem")
	if err := os.WriteFile(corrupt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileAnchorSource(corrupt).AnchorCertificates(t.Context()); !errors.Is(err, ErrCABundleParse{}) {
		t.Errorf("corrupt certificate = %v, want ErrCABundleParse", err)
	}

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("no pem here"), 0o600); err != nil {
		t.Fatal(err)
	}
	anchor, _ := NewAnchor(NewFileAnchorSource(empty))
	if _, err := anchor.CAPool(t.Context()); !errors.Is(err, ErrAnchorEmpty{}) {
		t.Errorf("bundle with no certificates = %v, want ErrAnchorEmpty", err)
	}
}

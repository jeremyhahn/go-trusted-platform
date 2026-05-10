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

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// TestNewClient_RejectsEmptyAddress confirms the canonical address
// validation contract.
func TestNewClient_RejectsEmptyAddress(t *testing.T) {
	if _, err := NewClient(ClientConfig{Address: ""}); err == nil {
		t.Fatal("expected ErrEmptyAddress")
	} else {
		var e *ErrEmptyAddress
		if !errors.As(err, &e) {
			t.Fatalf("expected *ErrEmptyAddress, got %T: %v", err, err)
		}
	}
}

// TestBuildEnrollRequest_RejectsUnknownType ensures only canonical
// factor types are accepted.
func TestBuildEnrollRequest_RejectsUnknownType(t *testing.T) {
	c := &Client{}
	_, err := c.buildEnrollRequest(t.Context(), &AddFactorRequest{Type: "totp", Label: "x"})
	var typeErr *ErrInvalidFactorType
	if !errors.As(err, &typeErr) {
		t.Fatalf("expected *ErrInvalidFactorType, got %T: %v", err, err)
	}
}

// TestBuildEnrollRequest_RequiresLabel verifies the --label flag is
// always required.
func TestBuildEnrollRequest_RequiresLabel(t *testing.T) {
	c := &Client{}
	_, err := c.buildEnrollRequest(t.Context(), &AddFactorRequest{Type: "mtls"})
	var labelErr *ErrMissingLabel
	if !errors.As(err, &labelErr) {
		t.Fatalf("expected *ErrMissingLabel, got %T: %v", err, err)
	}
}

// TestBuildEnrollRequest_MTLSRequiresCert verifies the mtls path
// rejects missing --cert.
func TestBuildEnrollRequest_MTLSRequiresCert(t *testing.T) {
	c := &Client{}
	_, err := c.buildEnrollRequest(t.Context(), &AddFactorRequest{Type: "mtls", Label: "test"})
	var certErr *ErrMissingCertPath
	if !errors.As(err, &certErr) {
		t.Fatalf("expected *ErrMissingCertPath, got %T: %v", err, err)
	}
}

// TestBuildEnrollRequest_MTLSCertFingerprint round-trips a generated
// PEM cert through the helper and asserts the fingerprint is set.
func TestBuildEnrollRequest_MTLSCertFingerprint(t *testing.T) {
	c := &Client{}
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "test.pem")
	writeTestCertPEM(t, certPath)

	req, err := c.buildEnrollRequest(t.Context(), &AddFactorRequest{
		Type:     "mtls",
		Label:    "test",
		User:     "alice",
		CertPath: certPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.FactorName != "mtls" {
		t.Errorf("expected factor name mtls, got %q", req.FactorName)
	}
	if req.Subject != "alice" {
		t.Errorf("expected subject alice, got %q", req.Subject)
	}
	if req.MethodParams["credential_sha256"] == nil {
		t.Error("expected credential_sha256 in MethodParams")
	}
	if req.MethodParams["cert_cn"] != "test-cn" {
		t.Errorf("expected cert_cn=test-cn, got %v", req.MethodParams["cert_cn"])
	}
}

// TestLoadCertFingerprintAndMetadata_BadPath surfaces a wrapped error.
func TestLoadCertFingerprintAndMetadata_BadPath(t *testing.T) {
	if _, _, err := loadCertFingerprintAndMetadata("/path/that/does/not/exist"); err == nil {
		t.Fatal("expected error for missing file")
	} else {
		var crErr *ErrCertRead
		if !errors.As(err, &crErr) {
			t.Fatalf("expected *ErrCertRead, got %T: %v", err, err)
		}
	}
}

// TestLoadCertFingerprintAndMetadata_NotPEM surfaces a wrapped error.
func TestLoadCertFingerprintAndMetadata_NotPEM(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "junk.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCertFingerprintAndMetadata(path); err == nil {
		t.Fatal("expected error for non-PEM file")
	} else {
		var crErr *ErrCertRead
		if !errors.As(err, &crErr) {
			t.Fatalf("expected *ErrCertRead, got %T: %v", err, err)
		}
	}
}

// writeTestCertPEM creates a self-signed test certificate at path.
func writeTestCertPEM(t *testing.T, path string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cn"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// TestResolveSubject_NilSDKReturnsUsernameUnchanged ensures the helper
// gracefully handles a Client without a connected SDK (e.g. tests that
// call buildEnrollRequest directly). The username must pass through so
// existing tests like TestBuildEnrollRequest_MTLSCertFingerprint
// continue to assert Subject == "alice".
func TestResolveSubject_NilSDKReturnsUsernameUnchanged(t *testing.T) {
	c := &Client{}
	subject, err := c.resolveSubject(t.Context(), "tenant-1", "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "alice" {
		t.Errorf("expected 'alice' passthrough, got %q", subject)
	}
}

// TestResolveSubject_EmptyUserReturnsEmpty ensures an empty username is
// passed through (server-determined identity).
func TestResolveSubject_EmptyUserReturnsEmpty(t *testing.T) {
	c := &Client{}
	subject, err := c.resolveSubject(t.Context(), "tenant-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "" {
		t.Errorf("expected empty subject, got %q", subject)
	}
}

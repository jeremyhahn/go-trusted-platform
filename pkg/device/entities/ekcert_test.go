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

package entities

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

// newTestEKCertPEM generates a self-signed ECDSA certificate PEM for
// EK-cert validation tests.
func newTestEKCertPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestParseEKCertPEM_Valid verifies a well-formed PEM certificate parses
// and returns the decoded X.509 certificate.
func TestParseEKCertPEM_Valid(t *testing.T) {
	certPEM := newTestEKCertPEM(t)

	cert, err := ParseEKCertPEM(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if cert.Subject.CommonName != "test-ek" {
		t.Fatalf("unexpected subject CN: %s", cert.Subject.CommonName)
	}
}

// TestParseEKCertPEM_NotPEM verifies non-PEM input is rejected with the
// typed ErrEKCertNotPEM.
func TestParseEKCertPEM_NotPEM(t *testing.T) {
	cert, err := ParseEKCertPEM("this is not pem data")
	if cert != nil {
		t.Fatal("expected nil certificate for non-PEM input")
	}
	var notPEM ErrEKCertNotPEM
	if !errors.As(err, &notPEM) {
		t.Fatalf("expected ErrEKCertNotPEM, got %T: %v", err, err)
	}
}

// TestParseEKCertPEM_InvalidDER verifies a PEM block whose contents are
// not a certificate is rejected with the typed ErrEKCertInvalid, and
// that the cause is unwrappable.
func TestParseEKCertPEM_InvalidDER(t *testing.T) {
	bogus := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")}))

	cert, err := ParseEKCertPEM(bogus)
	if cert != nil {
		t.Fatal("expected nil certificate for invalid DER")
	}
	var invalid ErrEKCertInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrEKCertInvalid, got %T: %v", err, err)
	}
	if invalid.Unwrap() == nil {
		t.Fatal("expected wrapped cause")
	}
}

// TestValidateEKCertPEM verifies the tri-state validation contract:
// empty passes, valid PEM passes, malformed values fail.
func TestValidateEKCertPEM(t *testing.T) {
	certPEM := newTestEKCertPEM(t)

	tests := []struct {
		name    string
		pemData string
		wantErr bool
	}{
		{name: "empty is valid (no prestage)", pemData: "", wantErr: false},
		{name: "valid PEM certificate", pemData: certPEM, wantErr: false},
		{name: "not PEM", pemData: "garbage", wantErr: true},
		{name: "PEM but not a certificate", pemData: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01}})), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEKCertPEM(tc.pemData)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestEKSerialFromCertPEM pins the one EK-serial derivation: the decimal
// X.509 serial for a valid certificate, the typed parse errors otherwise.
func TestEKSerialFromCertPEM(t *testing.T) {
	certPEM := newTestEKCertPEM(t)
	cert, err := ParseEKCertPEM(certPEM)
	if err != nil {
		t.Fatalf("ParseEKCertPEM: %v", err)
	}
	serial, err := EKSerialFromCertPEM(certPEM)
	if err != nil {
		t.Fatalf("EKSerialFromCertPEM: %v", err)
	}
	if serial != cert.SerialNumber.String() {
		t.Fatalf("serial = %q, want %q", serial, cert.SerialNumber.String())
	}

	if _, err := EKSerialFromCertPEM(""); !errors.Is(err, ErrEKCertNotPEM{}) {
		t.Fatalf("empty input: expected ErrEKCertNotPEM, got %v", err)
	}
	if _, err := EKSerialFromCertPEM("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"); err == nil {
		t.Fatal("garbage DER must not yield a serial")
	}
}

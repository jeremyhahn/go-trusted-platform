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

// Package issuancetest provides a CA that really certifies CSRs, for the
// tests of every transport that issues certificates from a CSR.
package issuancetest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// CA certifies CSRs with a throwaway root, as the platform CA's SignCSR
// does, and records the options it was asked to sign with.
type CA struct {
	Key  *rsa.PrivateKey
	Root *x509.Certificate
	// Opts is the last SignCSR's options; nil until a CSR reaches the CA.
	Opts *quicbaasca.SignOptions
	// Err, when set, is what SignCSR fails with.
	Err error
}

// NewCA returns a CA with a fresh root.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key := RSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "issuancetest root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issuancetest root: %v", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("issuancetest root: %v", err)
	}
	return &CA{Key: key, Root: root}
}

// SignCSR certifies the CSR's key under the CSR's subject.
func (c *CA) SignCSR(_ context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	c.Opts = opts
	if c.Err != nil {
		return nil, c.Err
	}
	var der []byte
	if block, _ := pem.Decode(csrPEM); block != nil {
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, max(opts.ValidityDays, 1)),
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.Root, csr.PublicKey, c.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

// RSAKey returns a fresh RSA-2048 key, the size of a Pi fleet key.
func RSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("issuancetest key: %v", err)
	}
	return key
}

// CSR returns a PEM CSR for cn, signed by signer.
func CSR(t testing.TB, signer crypto.Signer, cn string) []byte {
	t.Helper()
	return CSRFrom(t, signer, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}})
}

// CSRFrom returns a PEM CSR built from tmpl, signed by signer.
func CSRFrom(t testing.TB, signer crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		t.Fatalf("issuancetest CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

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

//go:build integration

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func signedTestCRL(t *testing.T, issuer pkix.Name) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               issuer,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(time.Hour),
	}, caCert, key)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return crlDER
}

func TestGetCRLResult_SetIssuerFromData(t *testing.T) {
	issuer := pkix.Name{CommonName: "Platform Intermediate CA", Organization: []string{"Example"}}
	result := &GetCRLResult{Data: signedTestCRL(t, issuer)}

	if err := result.setIssuerFromData("gRPC"); err != nil {
		t.Fatalf("setIssuerFromData: %v", err)
	}
	if result.Issuer != issuer.String() {
		t.Fatalf("Issuer = %q, want %q", result.Issuer, issuer.String())
	}
}

func TestGetCRLResult_SetIssuerFromDataRefusesMissingOrBadData(t *testing.T) {
	missing := &GetCRLResult{}
	var missingErr ErrCRLDataMissing
	if err := missing.setIssuerFromData("MCP"); !errors.As(err, &missingErr) {
		t.Fatalf("empty data: err = %v, want ErrCRLDataMissing", err)
	}

	garbage := &GetCRLResult{Data: []byte("not a CRL")}
	var parseErr ErrCRLParseFailed
	if err := garbage.setIssuerFromData("REST"); !errors.As(err, &parseErr) {
		t.Fatalf("garbage data: err = %v, want ErrCRLParseFailed", err)
	}
	if garbage.Issuer != "" {
		t.Fatalf("Issuer = %q after a parse failure, want empty", garbage.Issuer)
	}
}

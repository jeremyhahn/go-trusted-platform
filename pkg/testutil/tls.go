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

// Package testutil provides shared test utilities: wire-parity helpers for the
// client/server ratchets (wireparity.go) and helpers for generating TLS
// certificates and configurations used across the platform test suite.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestTLSBundle holds CA, server, and client TLS materials for testing.
type TestTLSBundle struct {
	CACert     *x509.Certificate
	CACertPEM  []byte
	CAPool     *x509.CertPool
	ServerCert tls.Certificate
	ClientCert tls.Certificate
}

// GenerateTestTLSBundle creates a complete TLS bundle with a self-signed CA,
// server certificate, and client certificate. The CA uses ECDSA P-256. The
// server certificate includes SANs for localhost and 127.0.0.1. All
// certificates are valid for 1 hour.
func GenerateTestTLSBundle(t *testing.T) *TestTLSBundle {
	t.Helper()

	now := time.Now()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.Add(time.Hour)

	// Generate CA key pair
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testutil: failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Platform CA"},
			CommonName:   "Test Platform CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(time.Hour), // CA outlives leaf certs
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("testutil: failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("testutil: failed to parse CA certificate: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Generate server certificate
	serverCert := generateLeafCert(t, caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Platform Server"},
			CommonName:   "localhost",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	})

	// Generate client certificate
	clientCert := generateLeafCert(t, caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Platform Client"},
			CommonName:   "test-client",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	})

	return &TestTLSBundle{
		CACert:     caCert,
		CACertPEM:  caCertPEM,
		CAPool:     caPool,
		ServerCert: serverCert,
		ClientCert: clientCert,
	}
}

// ServerTLSConfig returns a tls.Config suitable for test servers. It enforces
// TLS 1.3 minimum and requires client certificates verified against the test CA.
func (b *TestTLSBundle) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{b.ServerCert},
		ClientCAs:    b.CAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig returns a tls.Config suitable for test clients. It enforces
// TLS 1.3 minimum and verifies the server certificate against the test CA.
func (b *TestTLSBundle) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{b.ClientCert},
		RootCAs:      b.CAPool,
		MinVersion:   tls.VersionTLS13,
	}
}

// generateLeafCert creates a leaf certificate signed by the given CA and
// returns it as a tls.Certificate with the private key attached.
func generateLeafCert(
	t *testing.T,
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	template *x509.Certificate,
) tls.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testutil: failed to generate leaf key: %v", err)
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("testutil: failed to create leaf certificate: %v", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertDER,
	})

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("testutil: failed to marshal leaf key: %v", err)
	}

	leafKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: leafKeyDER,
	})

	tlsCert, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		t.Fatalf("testutil: failed to create tls.Certificate: %v", err)
	}

	return tlsCert
}

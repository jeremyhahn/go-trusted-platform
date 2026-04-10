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
	"context"
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
	"sync"
	"testing"
	"time"
)

func TestNewMTLSProvider(t *testing.T) {
	t.Run("creates provider with in-memory certs", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if p == nil {
			t.Fatal("NewMTLSProvider returned nil")
		}
		if p.Type() != AuthTypeMTLS {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeMTLS)
		}
	})

	t.Run("creates provider with file-based certs", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))
		tempDir := t.TempDir()

		certFile := filepath.Join(tempDir, "client.crt")
		keyFile := filepath.Join(tempDir, "client.key")
		caFile := filepath.Join(tempDir, "ca.crt")

		writeFile(t, certFile, certPEM)
		writeFile(t, keyFile, keyPEM)
		writeFile(t, caFile, caPEM)

		p, err := NewMTLSProvider(
			WithCertFile(certFile),
			WithKeyFile(keyFile),
			WithCAFile(caFile),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if p == nil {
			t.Fatal("NewMTLSProvider returned nil")
		}
	})

	t.Run("returns error for missing certificate", func(t *testing.T) {
		_, err := NewMTLSProvider(
			WithKeyPEM([]byte("key")),
		)

		if !errors.Is(err, ErrNoCertificate) {
			t.Errorf("NewMTLSProvider() error = %v, want %v", err, ErrNoCertificate)
		}
	})

	t.Run("returns error for missing key", func(t *testing.T) {
		certPEM, _, _ := generateTestCertificates(t, time.Now().Add(time.Hour))

		_, err := NewMTLSProvider(
			WithCertPEM(certPEM),
		)

		if !errors.Is(err, ErrNoPrivateKey) {
			t.Errorf("NewMTLSProvider() error = %v, want %v", err, ErrNoPrivateKey)
		}
	})

	t.Run("returns error for invalid certificate file", func(t *testing.T) {
		_, err := NewMTLSProvider(
			WithCertFile("/nonexistent/path/cert.pem"),
			WithKeyFile("/nonexistent/path/key.pem"),
		)

		var certErr ErrCertificateLoadFailed
		if !errors.As(err, &certErr) {
			t.Errorf("NewMTLSProvider() error = %v, want ErrCertificateLoadFailed", err)
		}
	})

	t.Run("returns error for invalid certificate PEM", func(t *testing.T) {
		_, err := NewMTLSProvider(
			WithCertPEM([]byte("invalid cert")),
			WithKeyPEM([]byte("invalid key")),
		)

		var certErr ErrCertificateLoadFailed
		if !errors.As(err, &certErr) {
			t.Errorf("NewMTLSProvider() error = %v, want ErrCertificateLoadFailed", err)
		}
	})

	t.Run("sets server name", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
			WithServerName("example.com"),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		if tlsConfig.ServerName != "example.com" {
			t.Errorf("ServerName = %v, want 'example.com'", tlsConfig.ServerName)
		}
	})

	t.Run("enforces TLS 1.3 minimum", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %v, want TLS 1.3 (%v)", tlsConfig.MinVersion, tls.VersionTLS13)
		}
		if tlsConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify must be false")
		}
	})
}

func TestMTLSProvider_GetToken(t *testing.T) {
	t.Run("returns ErrNoToken", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		_, tokenErr := p.GetToken(context.Background())
		if !errors.Is(tokenErr, ErrNoToken) {
			t.Errorf("GetToken() error = %v, want %v", tokenErr, ErrNoToken)
		}
	})
}

func TestMTLSProvider_GetTLSConfig(t *testing.T) {
	t.Run("returns TLS config with certificates", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}

		if len(tlsConfig.Certificates) != 1 {
			t.Errorf("len(Certificates) = %v, want 1", len(tlsConfig.Certificates))
		}

		if tlsConfig.MinVersion != tls.VersionTLS13 {
			t.Error("MinVersion should be TLS 1.3")
		}

		if tlsConfig.RootCAs == nil {
			t.Error("RootCAs should not be nil")
		}
	})

	t.Run("uses system cert pool when no CA specified", func(t *testing.T) {
		certPEM, keyPEM, _ := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		tlsConfig := p.GetTLSConfig()
		if tlsConfig == nil {
			t.Fatal("GetTLSConfig() should not be nil")
		}
		// RootCAs should be non-nil (system pool or empty pool)
	})
}

func TestMTLSProvider_Refresh(t *testing.T) {
	t.Run("reloads certificates from files", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))
		tempDir := t.TempDir()

		certFile := filepath.Join(tempDir, "client.crt")
		keyFile := filepath.Join(tempDir, "client.key")
		caFile := filepath.Join(tempDir, "ca.crt")

		writeFile(t, certFile, certPEM)
		writeFile(t, keyFile, keyPEM)
		writeFile(t, caFile, caPEM)

		p, err := NewMTLSProvider(
			WithCertFile(certFile),
			WithKeyFile(keyFile),
			WithCAFile(caFile),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		originalExpiry := p.NotAfter()

		// Generate new certificates with later expiry
		newCertPEM, newKeyPEM, newCAPEM := generateTestCertificates(t, time.Now().Add(2*time.Hour))
		writeFile(t, certFile, newCertPEM)
		writeFile(t, keyFile, newKeyPEM)
		writeFile(t, caFile, newCAPEM)

		// Refresh
		err = p.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}

		// Expiry should be different
		newExpiry := p.NotAfter()
		if newExpiry == originalExpiry {
			t.Error("Certificate expiry should have changed after refresh")
		}
	})

	t.Run("reloads in-memory certificates", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		// Refresh should succeed (reloads from stored PEM)
		err = p.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
	})
}

func TestMTLSProvider_IsExpired(t *testing.T) {
	t.Run("returns false for valid certificate", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if p.IsExpired() {
			t.Error("IsExpired() should return false for valid certificate")
		}
	})

	t.Run("returns true for expired certificate", func(t *testing.T) {
		// Generate a certificate that expired 1 hour ago
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(-time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if !p.IsExpired() {
			t.Error("IsExpired() should return true for expired certificate")
		}
	})
}

func TestMTLSProvider_Type(t *testing.T) {
	t.Run("returns AuthTypeMTLS", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if p.Type() != AuthTypeMTLS {
			t.Errorf("Type() = %v, want %v", p.Type(), AuthTypeMTLS)
		}
	})
}

func TestMTLSProvider_NotAfter(t *testing.T) {
	t.Run("returns certificate expiration", func(t *testing.T) {
		notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
		certPEM, keyPEM, caPEM := generateTestCertificatesWithNotAfter(t, notAfter)

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if p.NotAfter() != notAfter.Unix() {
			t.Errorf("NotAfter() = %v, want %v", p.NotAfter(), notAfter.Unix())
		}
	})
}

func TestMTLSProvider_ExpiresIn(t *testing.T) {
	t.Run("returns positive duration for valid certificate", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		expiresIn := p.ExpiresIn()
		if expiresIn <= 0 {
			t.Errorf("ExpiresIn() = %v, want positive duration", expiresIn)
		}
		// Should be approximately 1 hour
		if expiresIn < 59*time.Minute || expiresIn > 61*time.Minute {
			t.Errorf("ExpiresIn() = %v, expected ~1 hour", expiresIn)
		}
	})

	t.Run("returns 0 for expired certificate", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(-time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		if p.ExpiresIn() != 0 {
			t.Errorf("ExpiresIn() = %v, want 0", p.ExpiresIn())
		}
	})
}

func TestMTLSProvider_ConcurrentAccess(t *testing.T) {
	t.Run("handles concurrent GetTLSConfig calls", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		var wg sync.WaitGroup
		iterations := 100

		for range iterations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = p.GetTLSConfig()
				_ = p.IsExpired()
				_ = p.NotAfter()
				_ = p.ExpiresIn()
			}()
		}

		wg.Wait()
		// Test passes if no race condition detected
	})

	t.Run("handles concurrent Refresh calls", func(t *testing.T) {
		certPEM, keyPEM, caPEM := generateTestCertificates(t, time.Now().Add(time.Hour))

		p, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM(caPEM),
		)
		if err != nil {
			t.Fatalf("NewMTLSProvider() error = %v", err)
		}

		var wg sync.WaitGroup
		iterations := 10

		for range iterations {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = p.Refresh(context.Background())
			}()
		}

		wg.Wait()
		// Test passes if no race condition detected
	})
}

func TestMTLSProvider_CALoadFailed(t *testing.T) {
	t.Run("returns error for invalid CA file", func(t *testing.T) {
		certPEM, keyPEM, _ := generateTestCertificates(t, time.Now().Add(time.Hour))

		_, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAFile("/nonexistent/ca.crt"),
		)

		var caErr ErrCALoadFailed
		if !errors.As(err, &caErr) {
			t.Errorf("NewMTLSProvider() error = %v, want ErrCALoadFailed", err)
		}
	})

	t.Run("returns error for invalid CA PEM", func(t *testing.T) {
		certPEM, keyPEM, _ := generateTestCertificates(t, time.Now().Add(time.Hour))

		_, err := NewMTLSProvider(
			WithCertPEM(certPEM),
			WithKeyPEM(keyPEM),
			WithCAPEM([]byte("invalid ca pem")),
		)

		var caErr ErrCALoadFailed
		if !errors.As(err, &caErr) {
			t.Errorf("NewMTLSProvider() error = %v, want ErrCALoadFailed", err)
		}
	})
}

// Helper functions for generating test certificates

func generateTestCertificates(t *testing.T, notAfter time.Time) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	return generateTestCertificatesWithNotAfter(t, notAfter)
}

func generateTestCertificatesWithNotAfter(t *testing.T, notAfter time.Time) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()

	// Generate CA key and certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter.Add(24 * time.Hour), // CA expires later than client
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert,
	})

	// Generate client key and certificate
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "Test Client",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Parse the CA certificate for signing
	parsedCA, err := x509.ParseCertificate(caCert)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	clientCert, err := x509.CreateCertificate(rand.Reader, clientTemplate, parsedCA, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCert,
	})

	keyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %v", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return certPEM, keyPEM, caPEM
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write file %s: %v", path, err)
	}
}

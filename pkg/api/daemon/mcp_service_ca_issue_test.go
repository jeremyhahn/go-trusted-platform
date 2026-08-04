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

package daemon

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"log/slog"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// =============================================================================
// CAIssue Nil Service Tests (validates error handling path)
// =============================================================================

func TestMCPServiceProvider_CAIssue_NilService_AllFields(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with complete request to exercise request building path
	req := &mcp.CAIssueRequest{
		CommonName:         "test.example.com",
		Organization:       "Test Organization",
		OrganizationalUnit: "Test Unit",
		Country:            "US",
		Province:           "California",
		Locality:           "San Francisco",
		DNSNames:           []string{"www.example.com", "api.example.com"},
		IPAddresses:        []string{"192.168.1.1", "10.0.0.1"},
		EmailAddresses:     []string{"admin@example.com"},
		URIs:               []string{"spiffe://cluster.local/ns/default/sa/service"},
		ValidDays:          365,
		Algorithm:          "RSA-2048",
		StoreType:          "software",
		KeyUsage:           []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsage:        []string{"serverAuth", "clientAuth"},
		IsCA:               false,
		MaxPathLen:         0,
	}

	_, err := provider.CAIssue(ctx, req)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAIssue_NilService_CACertificate(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test CA certificate request
	req := &mcp.CAIssueRequest{
		CommonName:   "Intermediate CA",
		Organization: "Example Corp",
		Country:      "US",
		IsCA:         true,
		MaxPathLen:   2,
		KeyUsage:     []string{"certSign", "crlSign"},
		ValidDays:    3650,
		Algorithm:    "ECDSA-P384",
	}

	_, err := provider.CAIssue(ctx, req)
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAIssue_NilService_VariousAlgorithms(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	algorithms := []string{
		"RSA",
		"RSA-2048",
		"RSA-3072",
		"RSA-4096",
		"ECDSA",
		"ECDSA-P256",
		"ECDSA-P384",
		"ECDSA-P521",
		"ED25519",
	}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			req := &mcp.CAIssueRequest{
				CommonName: "test.example.com",
				Algorithm:  alg,
				ValidDays:  365,
			}

			_, err := provider.CAIssue(ctx, req)
			if err == nil {
				t.Fatal("expected error for nil CA service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != "ca" {
				t.Errorf("expected service='ca', got %q", svcErr.Service)
			}
		})
	}
}

// =============================================================================
// CAList Nil Service Tests
// =============================================================================

func TestMCPServiceProvider_CAList_NilService_DefaultPageSize(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with limit=0 which should use default page size
	_, err := provider.CAList(ctx, 0, "", "")
	if err == nil {
		t.Fatal("expected error for nil CA service")
	}

	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "ca" {
		t.Errorf("expected service='ca', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_CAList_NilService_CustomPageSize(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	testCases := []struct {
		name   string
		limit  int
		cursor string
		status string
	}{
		{"small page", 5, "", ""},
		{"medium page", 25, "", "active"},
		{"large page", 100, "", "revoked"},
		{"with cursor", 10, "abc123", ""},
		{"all params", 50, "cursor-token", "expired"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.CAList(ctx, tc.limit, tc.cursor, tc.status)
			if err == nil {
				t.Fatal("expected error for nil CA service")
			}

			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != "ca" {
				t.Errorf("expected service='ca', got %q", svcErr.Service)
			}
		})
	}
}

// =============================================================================
// buildKeyAttributes Tests - Comprehensive Algorithm Coverage
// =============================================================================

func TestBuildKeyAttributes_AESAlgorithms(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		expectAlg xkmssdk.SymmetricAlgorithm
	}{
		{"AES128", "AES128", xkmssdk.SymmetricAES128GCM},
		{"AES-128", "AES-128", xkmssdk.SymmetricAES128GCM},
		{"AES128GCM", "AES128GCM", xkmssdk.SymmetricAES128GCM},
		{"AES-128-GCM", "AES-128-GCM", xkmssdk.SymmetricAES128GCM},
		{"aes128 lowercase", "aes128", xkmssdk.SymmetricAES128GCM},
		{"AES256", "AES256", xkmssdk.SymmetricAES256GCM},
		{"AES-256", "AES-256", xkmssdk.SymmetricAES256GCM},
		{"AES256GCM", "AES256GCM", xkmssdk.SymmetricAES256GCM},
		{"AES-256-GCM", "AES-256-GCM", xkmssdk.SymmetricAES256GCM},
		{"aes256 lowercase", "aes256", xkmssdk.SymmetricAES256GCM},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.SymmetricAlgorithm != tc.expectAlg {
				t.Errorf("expected SymmetricAlgorithm %v, got %v", tc.expectAlg, attrs.SymmetricAlgorithm)
			}
			if attrs.KeyType != xkmssdk.KeyTypeEncryption {
				t.Errorf("expected KeyType Encryption, got %v", attrs.KeyType)
			}
		})
	}
}

func TestBuildKeyAttributes_ChaChaAlgorithms(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		expectAlg xkmssdk.SymmetricAlgorithm
	}{
		{"CHACHA20", "CHACHA20", xkmssdk.SymmetricChaCha20Poly1305},
		{"CHACHA20POLY1305", "CHACHA20POLY1305", xkmssdk.SymmetricChaCha20Poly1305},
		{"CHACHA20-POLY1305", "CHACHA20-POLY1305", xkmssdk.SymmetricChaCha20Poly1305},
		{"chacha20 lowercase", "chacha20", xkmssdk.SymmetricChaCha20Poly1305},
		{"XCHACHA20", "XCHACHA20", xkmssdk.SymmetricXChaCha20Poly1305},
		{"XCHACHA20POLY1305", "XCHACHA20POLY1305", xkmssdk.SymmetricXChaCha20Poly1305},
		{"XCHACHA20-POLY1305", "XCHACHA20-POLY1305", xkmssdk.SymmetricXChaCha20Poly1305},
		{"xchacha20 lowercase", "xchacha20", xkmssdk.SymmetricXChaCha20Poly1305},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.SymmetricAlgorithm != tc.expectAlg {
				t.Errorf("expected SymmetricAlgorithm %v, got %v", tc.expectAlg, attrs.SymmetricAlgorithm)
			}
			if attrs.KeyType != xkmssdk.KeyTypeEncryption {
				t.Errorf("expected KeyType Encryption, got %v", attrs.KeyType)
			}
		})
	}
}

func TestBuildKeyAttributes_RSAAlgorithms(t *testing.T) {
	testCases := []struct {
		name       string
		algorithm  string
		expectSize int
	}{
		{"RSA", "RSA", 2048},
		{"RSA2048", "RSA2048", 2048},
		{"RSA-2048", "RSA-2048", 2048},
		{"rsa lowercase", "rsa", 2048},
		{"RSA3072", "RSA3072", 3072},
		{"RSA-3072", "RSA-3072", 3072},
		{"rsa3072 lowercase", "rsa3072", 3072},
		{"RSA4096", "RSA4096", 4096},
		{"RSA-4096", "RSA-4096", 4096},
		{"rsa4096 lowercase", "rsa4096", 4096},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.KeyAlgorithm != x509.RSA {
				t.Errorf("expected KeyAlgorithm RSA, got %v", attrs.KeyAlgorithm)
			}
			if attrs.KeyType != xkmssdk.KeyTypeSigning {
				t.Errorf("expected KeyType Signing, got %v", attrs.KeyType)
			}
			if attrs.RSAAttributes == nil {
				t.Fatal("expected RSAAttributes to be set")
			}
			if attrs.RSAAttributes.KeySize != tc.expectSize {
				t.Errorf("expected KeySize %d, got %d", tc.expectSize, attrs.RSAAttributes.KeySize)
			}
		})
	}
}

func TestBuildKeyAttributes_ECDSAAlgorithms(t *testing.T) {
	testCases := []struct {
		name        string
		algorithm   string
		expectCurve elliptic.Curve
	}{
		{"ECDSA", "ECDSA", elliptic.P256()},
		{"EC", "EC", elliptic.P256()},
		{"ECDSAP256", "ECDSAP256", elliptic.P256()},
		{"ECDSA-P256", "ECDSA-P256", elliptic.P256()},
		{"P256", "P256", elliptic.P256()},
		{"p256 lowercase", "p256", elliptic.P256()},
		{"ECDSAP384", "ECDSAP384", elliptic.P384()},
		{"ECDSA-P384", "ECDSA-P384", elliptic.P384()},
		{"P384", "P384", elliptic.P384()},
		{"p384 lowercase", "p384", elliptic.P384()},
		{"ECDSAP521", "ECDSAP521", elliptic.P521()},
		{"ECDSA-P521", "ECDSA-P521", elliptic.P521()},
		{"P521", "P521", elliptic.P521()},
		{"p521 lowercase", "p521", elliptic.P521()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.KeyAlgorithm != x509.ECDSA {
				t.Errorf("expected KeyAlgorithm ECDSA, got %v", attrs.KeyAlgorithm)
			}
			if attrs.KeyType != xkmssdk.KeyTypeSigning {
				t.Errorf("expected KeyType Signing, got %v", attrs.KeyType)
			}
			if attrs.ECCAttributes == nil {
				t.Fatal("expected ECCAttributes to be set")
			}
			if attrs.ECCAttributes.Curve.Params().Name != tc.expectCurve.Params().Name {
				t.Errorf("expected Curve %s, got %s", tc.expectCurve.Params().Name, attrs.ECCAttributes.Curve.Params().Name)
			}
		})
	}
}

func TestBuildKeyAttributes_ED25519(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
	}{
		{"ED25519 uppercase", "ED25519"},
		{"ed25519 lowercase", "ed25519"},
		{"Ed25519 mixed case", "Ed25519"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.KeyAlgorithm != x509.Ed25519 {
				t.Errorf("expected KeyAlgorithm Ed25519, got %v", attrs.KeyAlgorithm)
			}
			if attrs.KeyType != xkmssdk.KeyTypeSigning {
				t.Errorf("expected KeyType Signing, got %v", attrs.KeyType)
			}
			// ED25519 should not have RSA or ECC attributes
			if attrs.RSAAttributes != nil {
				t.Error("expected RSAAttributes to be nil for ED25519")
			}
			if attrs.ECCAttributes != nil {
				t.Error("expected ECCAttributes to be nil for ED25519")
			}
		})
	}
}

func TestBuildKeyAttributes_InvalidAlgorithm(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
	}{
		{"empty string", ""},
		{"unknown algorithm", "UNKNOWN"},
		{"typo", "AE256"},
		{"invalid format", "RSA-123"},
		{"partial match", "AES"},
		{"partial RSA", "RS256"},
		{"random string", "foobar"},
		{"numeric only", "12345"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			_, err := buildKeyAttributes(req)
			if err == nil {
				t.Fatal("expected error for invalid algorithm")
			}

			kmsErr, ok := err.(ErrKMSInvalidAlgorithm)
			if !ok {
				t.Fatalf("expected ErrKMSInvalidAlgorithm, got %T: %v", err, err)
			}
			if kmsErr.Algorithm != tc.algorithm {
				t.Errorf("expected Algorithm %q in error, got %q", tc.algorithm, kmsErr.Algorithm)
			}
		})
	}
}

func TestBuildKeyAttributes_CommonNamePreserved(t *testing.T) {
	testCases := []struct {
		name     string
		keyName  string
		expected string
	}{
		{"simple name", "my-key", "my-key"},
		{"with dashes", "my-test-key", "my-test-key"},
		{"with underscores", "my_test_key", "my_test_key"},
		{"with numbers", "key-123-test", "key-123-test"},
		{"empty name", "", ""},
		{"long name", "this-is-a-very-long-key-name-for-testing", "this-is-a-very-long-key-name-for-testing"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      tc.keyName,
				Algorithm: "AES256",
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.CN != tc.expected {
				t.Errorf("expected CN %q, got %q", tc.expected, attrs.CN)
			}
		})
	}
}

func TestBuildKeyAttributes_WhitespaceHandling(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		expectAlg xkmssdk.SymmetricAlgorithm
	}{
		{"leading space", " AES256", xkmssdk.SymmetricAES256GCM},
		{"trailing space", "AES256 ", xkmssdk.SymmetricAES256GCM},
		{"both spaces", " AES256 ", xkmssdk.SymmetricAES256GCM},
		{"tabs", "\tAES256\t", xkmssdk.SymmetricAES256GCM},
		{"mixed whitespace", " \tAES256\t ", xkmssdk.SymmetricAES256GCM},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.SymmetricAlgorithm != tc.expectAlg {
				t.Errorf("expected SymmetricAlgorithm %v, got %v", tc.expectAlg, attrs.SymmetricAlgorithm)
			}
		})
	}
}

func TestBuildKeyAttributes_CaseInsensitivity(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm string
		expectAlg xkmssdk.SymmetricAlgorithm
	}{
		{"uppercase", "AES256GCM", xkmssdk.SymmetricAES256GCM},
		{"lowercase", "aes256gcm", xkmssdk.SymmetricAES256GCM},
		{"mixed case", "Aes256Gcm", xkmssdk.SymmetricAES256GCM},
		{"alternating case", "aEs256gCm", xkmssdk.SymmetricAES256GCM},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: tc.algorithm,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if attrs.SymmetricAlgorithm != tc.expectAlg {
				t.Errorf("expected SymmetricAlgorithm %v, got %v", tc.expectAlg, attrs.SymmetricAlgorithm)
			}
		})
	}
}

func TestBuildKeyAttributes_SymmetricVsAsymmetric(t *testing.T) {
	// Test symmetric algorithms have correct attributes
	t.Run("symmetric AES256", func(t *testing.T) {
		req := &mcp.KMSCreateKeyRequest{
			Name:      "symmetric-key",
			Algorithm: "AES256",
		}

		attrs, err := buildKeyAttributes(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if attrs.KeyType != xkmssdk.KeyTypeEncryption {
			t.Errorf("expected KeyType Encryption for symmetric, got %v", attrs.KeyType)
		}
		if attrs.RSAAttributes != nil {
			t.Error("expected RSAAttributes to be nil for symmetric key")
		}
		if attrs.ECCAttributes != nil {
			t.Error("expected ECCAttributes to be nil for symmetric key")
		}
	})

	// Test asymmetric algorithms have correct attributes
	t.Run("asymmetric RSA", func(t *testing.T) {
		req := &mcp.KMSCreateKeyRequest{
			Name:      "asymmetric-key",
			Algorithm: "RSA2048",
		}

		attrs, err := buildKeyAttributes(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if attrs.KeyType != xkmssdk.KeyTypeSigning {
			t.Errorf("expected KeyType Signing for asymmetric, got %v", attrs.KeyType)
		}
		if attrs.RSAAttributes == nil {
			t.Error("expected RSAAttributes to be set for RSA key")
		}
	})

	t.Run("asymmetric ECDSA", func(t *testing.T) {
		req := &mcp.KMSCreateKeyRequest{
			Name:      "ecdsa-key",
			Algorithm: "ECDSA-P256",
		}

		attrs, err := buildKeyAttributes(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if attrs.KeyType != xkmssdk.KeyTypeSigning {
			t.Errorf("expected KeyType Signing for ECDSA, got %v", attrs.KeyType)
		}
		if attrs.ECCAttributes == nil {
			t.Error("expected ECCAttributes to be set for ECDSA key")
		}
	})
}

func TestBuildKeyAttributes_AllValidAlgorithms(t *testing.T) {
	// Comprehensive test of all supported algorithms
	validAlgorithms := []string{
		// AES
		"AES128", "AES-128", "AES128GCM", "AES-128-GCM",
		"AES256", "AES-256", "AES256GCM", "AES-256-GCM",
		// ChaCha
		"CHACHA20", "CHACHA20POLY1305", "CHACHA20-POLY1305",
		"XCHACHA20", "XCHACHA20POLY1305", "XCHACHA20-POLY1305",
		// RSA
		"RSA", "RSA2048", "RSA-2048",
		"RSA3072", "RSA-3072",
		"RSA4096", "RSA-4096",
		// ECDSA
		"ECDSA", "EC", "ECDSAP256", "ECDSA-P256", "P256",
		"ECDSAP384", "ECDSA-P384", "P384",
		"ECDSAP521", "ECDSA-P521", "P521",
		// Ed25519
		"ED25519",
	}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			req := &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: alg,
			}

			attrs, err := buildKeyAttributes(req)
			if err != nil {
				t.Errorf("algorithm %q should be valid but got error: %v", alg, err)
			}
			if attrs == nil {
				t.Errorf("algorithm %q should return non-nil attrs", alg)
			}
		})
	}
}

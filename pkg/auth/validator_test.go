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
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestValidateCertificate(t *testing.T) {
	ctx := context.Background()

	t.Run("nil certificate returns error", func(t *testing.T) {
		err := ValidateCertificate(ctx, nil, x509.NewCertPool())
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
		if _, ok := err.(ErrNilCertificate); !ok {
			t.Errorf("Expected ErrNilCertificate, got %T", err)
		}
	})

	t.Run("nil roots returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		cert := createTestCertificate(t, opts)

		err := ValidateCertificate(ctx, cert, nil)
		if err == nil {
			t.Error("Expected error for nil roots")
		}
		if _, ok := err.(ErrMissingTrustedRoots); !ok {
			t.Errorf("Expected ErrMissingTrustedRoots, got %T", err)
		}
	})

	t.Run("expired certificate returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notAfter = time.Now().Add(-1 * time.Hour)
		cert := createTestCertificate(t, opts)

		roots := x509.NewCertPool()
		roots.AddCert(cert)

		err := ValidateCertificate(ctx, cert, roots)
		if err == nil {
			t.Error("Expected error for expired certificate")
		}
		if _, ok := err.(ErrCertificateExpired); !ok {
			t.Errorf("Expected ErrCertificateExpired, got %T", err)
		}
	})

	t.Run("not yet valid certificate returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notBefore = time.Now().Add(1 * time.Hour)
		opts.notAfter = time.Now().Add(24 * time.Hour)
		cert := createTestCertificate(t, opts)

		roots := x509.NewCertPool()
		roots.AddCert(cert)

		err := ValidateCertificate(ctx, cert, roots)
		if err == nil {
			t.Error("Expected error for not yet valid certificate")
		}
	})

	t.Run("valid self-signed CA cert validates", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.isCA = true
		cert := createTestCertificate(t, opts)

		roots := x509.NewCertPool()
		roots.AddCert(cert)

		err := ValidateCertificate(ctx, cert, roots)
		if err != nil {
			t.Errorf("ValidateCertificate failed: %v", err)
		}
	})
}

func TestValidateIDevID(t *testing.T) {
	ctx := context.Background()

	t.Run("nil certificate returns error", func(t *testing.T) {
		err := ValidateIDevID(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
		if _, ok := err.(ErrNilCertificate); !ok {
			t.Errorf("Expected ErrNilCertificate, got %T", err)
		}
	})

	t.Run("certificate without digital signature returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.keyUsage = x509.KeyUsageKeyEncipherment
		cert := createTestCertificate(t, opts)

		err := ValidateIDevID(ctx, cert)
		if err == nil {
			t.Error("Expected error for missing DigitalSignature")
		}
		if _, ok := err.(ErrInvalidKeyUsage); !ok {
			t.Errorf("Expected ErrInvalidKeyUsage, got %T", err)
		}
	})

	t.Run("certificate with digital signature but no TPM OIDs returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.keyUsage = x509.KeyUsageDigitalSignature
		cert := createTestCertificate(t, opts)

		err := ValidateIDevID(ctx, cert)
		if err == nil {
			t.Error("Expected error for missing TPM OIDs")
		}
		if _, ok := err.(ErrTPMAttestationFailed); !ok {
			t.Errorf("Expected ErrTPMAttestationFailed, got %T", err)
		}
	})
}

func TestValidateIAK(t *testing.T) {
	ctx := context.Background()

	t.Run("nil certificate returns error", func(t *testing.T) {
		err := ValidateIAK(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
		if _, ok := err.(ErrNilCertificate); !ok {
			t.Errorf("Expected ErrNilCertificate, got %T", err)
		}
	})

	t.Run("certificate without digital signature returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.keyUsage = x509.KeyUsageKeyEncipherment
		cert := createTestCertificate(t, opts)

		err := ValidateIAK(ctx, cert)
		if err == nil {
			t.Error("Expected error for missing DigitalSignature")
		}
		if _, ok := err.(ErrInvalidKeyUsage); !ok {
			t.Errorf("Expected ErrInvalidKeyUsage, got %T", err)
		}
	})
}

func TestHasKeyUsage(t *testing.T) {
	t.Run("nil certificate returns false", func(t *testing.T) {
		if HasKeyUsage(nil, x509.KeyUsageDigitalSignature) {
			t.Error("Expected false for nil certificate")
		}
	})

	t.Run("has key usage", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		cert := createTestCertificate(t, opts)

		if !HasKeyUsage(cert, x509.KeyUsageDigitalSignature) {
			t.Error("Expected true for DigitalSignature")
		}
		if !HasKeyUsage(cert, x509.KeyUsageKeyEncipherment) {
			t.Error("Expected true for KeyEncipherment")
		}
		if HasKeyUsage(cert, x509.KeyUsageCertSign) {
			t.Error("Expected false for CertSign")
		}
	})
}

func TestHasExtKeyUsage(t *testing.T) {
	t.Run("nil certificate returns false", func(t *testing.T) {
		if HasExtKeyUsage(nil, x509.ExtKeyUsageClientAuth) {
			t.Error("Expected false for nil certificate")
		}
	})

	t.Run("has ext key usage", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		cert := createTestCertificate(t, opts)

		if !HasExtKeyUsage(cert, x509.ExtKeyUsageClientAuth) {
			t.Error("Expected true for ClientAuth")
		}
		if !HasExtKeyUsage(cert, x509.ExtKeyUsageServerAuth) {
			t.Error("Expected true for ServerAuth")
		}
		if HasExtKeyUsage(cert, x509.ExtKeyUsageCodeSigning) {
			t.Error("Expected false for CodeSigning")
		}
	})
}

func TestHasAnyExtKeyUsage(t *testing.T) {
	opts := defaultTestCertOptions()
	opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cert := createTestCertificate(t, opts)

	t.Run("has one of the usages", func(t *testing.T) {
		if !HasAnyExtKeyUsage(cert, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth) {
			t.Error("Expected true when one usage matches")
		}
	})

	t.Run("has none of the usages", func(t *testing.T) {
		if HasAnyExtKeyUsage(cert, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning) {
			t.Error("Expected false when no usage matches")
		}
	})
}

func TestRequireExtKeyUsage(t *testing.T) {
	opts := defaultTestCertOptions()
	opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cert := createTestCertificate(t, opts)

	t.Run("has required usage", func(t *testing.T) {
		err := RequireExtKeyUsage(cert, x509.ExtKeyUsageClientAuth)
		if err != nil {
			t.Errorf("RequireExtKeyUsage failed: %v", err)
		}
	})

	t.Run("missing required usage", func(t *testing.T) {
		err := RequireExtKeyUsage(cert, x509.ExtKeyUsageServerAuth)
		if err == nil {
			t.Error("Expected error for missing usage")
		}
		if _, ok := err.(ErrInvalidExtKeyUsage); !ok {
			t.Errorf("Expected ErrInvalidExtKeyUsage, got %T", err)
		}
	})
}

func TestIsClientAuthCertificate(t *testing.T) {
	t.Run("with ClientAuth", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		cert := createTestCertificate(t, opts)

		if !IsClientAuthCertificate(cert) {
			t.Error("Expected true for ClientAuth certificate")
		}
	})

	t.Run("with Any", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		cert := createTestCertificate(t, opts)

		if !IsClientAuthCertificate(cert) {
			t.Error("Expected true for Any certificate")
		}
	})

	t.Run("without ClientAuth", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert := createTestCertificate(t, opts)

		if IsClientAuthCertificate(cert) {
			t.Error("Expected false for ServerAuth-only certificate")
		}
	})
}

func TestIsServerAuthCertificate(t *testing.T) {
	t.Run("with ServerAuth", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert := createTestCertificate(t, opts)

		if !IsServerAuthCertificate(cert) {
			t.Error("Expected true for ServerAuth certificate")
		}
	})

	t.Run("without ServerAuth", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		cert := createTestCertificate(t, opts)

		if IsServerAuthCertificate(cert) {
			t.Error("Expected false for ClientAuth-only certificate")
		}
	})
}

func TestIsCACertificate(t *testing.T) {
	t.Run("nil certificate returns false", func(t *testing.T) {
		if IsCACertificate(nil) {
			t.Error("Expected false for nil certificate")
		}
	})

	t.Run("CA certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.isCA = true
		cert := createTestCertificate(t, opts)

		if !IsCACertificate(cert) {
			t.Error("Expected true for CA certificate")
		}
	})

	t.Run("non-CA certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.isCA = false
		cert := createTestCertificate(t, opts)

		if IsCACertificate(cert) {
			t.Error("Expected false for non-CA certificate")
		}
	})
}

func TestIsExpired(t *testing.T) {
	t.Run("nil certificate returns true", func(t *testing.T) {
		if !IsExpired(nil) {
			t.Error("Expected true for nil certificate")
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notAfter = time.Now().Add(-1 * time.Hour)
		cert := createTestCertificate(t, opts)

		if !IsExpired(cert) {
			t.Error("Expected true for expired certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		cert := createTestCertificate(t, opts)

		if IsExpired(cert) {
			t.Error("Expected false for valid certificate")
		}
	})
}

func TestIsNotYetValid(t *testing.T) {
	t.Run("nil certificate returns true", func(t *testing.T) {
		if !IsNotYetValid(nil) {
			t.Error("Expected true for nil certificate")
		}
	})

	t.Run("not yet valid certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notBefore = time.Now().Add(1 * time.Hour)
		opts.notAfter = time.Now().Add(24 * time.Hour)
		cert := createTestCertificate(t, opts)

		if !IsNotYetValid(cert) {
			t.Error("Expected true for not yet valid certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		cert := createTestCertificate(t, opts)

		if IsNotYetValid(cert) {
			t.Error("Expected false for valid certificate")
		}
	})
}

func TestValidityRemaining(t *testing.T) {
	t.Run("nil certificate returns zero", func(t *testing.T) {
		if ValidityRemaining(nil) != 0 {
			t.Error("Expected 0 for nil certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notAfter = time.Now().Add(24 * time.Hour)
		cert := createTestCertificate(t, opts)

		remaining := ValidityRemaining(cert)
		if remaining < 23*time.Hour || remaining > 25*time.Hour {
			t.Errorf("ValidityRemaining() = %v, expected approximately 24 hours", remaining)
		}
	})

	t.Run("expired certificate returns negative", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notAfter = time.Now().Add(-1 * time.Hour)
		cert := createTestCertificate(t, opts)

		remaining := ValidityRemaining(cert)
		if remaining >= 0 {
			t.Errorf("ValidityRemaining() = %v, expected negative for expired cert", remaining)
		}
	})
}

func TestOidEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []int
		b        []int
		expected bool
	}{
		{"equal", []int{1, 2, 3}, []int{1, 2, 3}, true},
		{"different values", []int{1, 2, 3}, []int{1, 2, 4}, false},
		{"different lengths", []int{1, 2, 3}, []int{1, 2}, false},
		{"both empty", []int{}, []int{}, true},
		{"one empty", []int{1}, []int{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := oidEqual(tt.a, tt.b); got != tt.expected {
				t.Errorf("oidEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

func TestExtKeyUsageToString(t *testing.T) {
	tests := []struct {
		usage    x509.ExtKeyUsage
		expected string
	}{
		{x509.ExtKeyUsageAny, "Any"},
		{x509.ExtKeyUsageServerAuth, "ServerAuth"},
		{x509.ExtKeyUsageClientAuth, "ClientAuth"},
		{x509.ExtKeyUsageCodeSigning, "CodeSigning"},
		{x509.ExtKeyUsageEmailProtection, "EmailProtection"},
		{x509.ExtKeyUsageIPSECEndSystem, "IPSECEndSystem"},
		{x509.ExtKeyUsageIPSECTunnel, "IPSECTunnel"},
		{x509.ExtKeyUsageIPSECUser, "IPSECUser"},
		{x509.ExtKeyUsageTimeStamping, "TimeStamping"},
		{x509.ExtKeyUsageOCSPSigning, "OCSPSigning"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "MicrosoftServerGatedCrypto"},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, "NetscapeServerGatedCrypto"},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "MicrosoftCommercialCodeSigning"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "MicrosoftKernelCodeSigning"},
		{x509.ExtKeyUsage(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := extKeyUsageToString(tt.usage); got != tt.expected {
				t.Errorf("extKeyUsageToString(%v) = %v, want %v", tt.usage, got, tt.expected)
			}
		})
	}
}

// createCertWithExtensions creates a certificate with custom extensions for testing.
func createCertWithExtensions(t *testing.T, extensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestValidateIDevID_WithTPMOIDs(t *testing.T) {
	ctx := context.Background()

	// Create a certificate with TPM manufacturer OID
	tpmManufacturerExt := pkix.Extension{
		Id:    oidTCGManufacturer,
		Value: []byte{0x04, 0x04, 'T', 'E', 'S', 'T'},
	}

	cert := createCertWithExtensions(t, []pkix.Extension{tpmManufacturerExt})

	err := ValidateIDevID(ctx, cert)
	if err != nil {
		t.Errorf("ValidateIDevID should pass with TPM manufacturer OID: %v", err)
	}
}

func TestValidateIAK_WithTPMOIDs(t *testing.T) {
	ctx := context.Background()

	// Create a certificate with TPM manufacturer OID
	tpmManufacturerExt := pkix.Extension{
		Id:    oidTCGManufacturer,
		Value: []byte{0x04, 0x04, 'T', 'E', 'S', 'T'},
	}

	cert := createCertWithExtensions(t, []pkix.Extension{tpmManufacturerExt})

	err := ValidateIAK(ctx, cert)
	if err != nil {
		t.Errorf("ValidateIAK should pass with TPM manufacturer OID: %v", err)
	}
}

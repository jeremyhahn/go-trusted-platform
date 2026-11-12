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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// createTestCertificate creates a self-signed test certificate.
func createTestCertificate(t *testing.T, opts testCertOptions) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         opts.commonName,
			Organization:       opts.organization,
			OrganizationalUnit: opts.orgUnit,
			SerialNumber:       opts.serialNumber,
		},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              opts.keyUsage,
		ExtKeyUsage:           opts.extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
		EmailAddresses:        opts.emailAddresses,
		DNSNames:              opts.dnsNames,
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

type testCertOptions struct {
	commonName     string
	organization   []string
	orgUnit        []string
	serialNumber   string
	notBefore      time.Time
	notAfter       time.Time
	keyUsage       x509.KeyUsage
	extKeyUsage    []x509.ExtKeyUsage
	isCA           bool
	emailAddresses []string
	dnsNames       []string
}

func defaultTestCertOptions() testCertOptions {
	now := time.Now()
	return testCertOptions{
		commonName:     "Test User",
		organization:   []string{"Test Org"},
		notBefore:      now.Add(-1 * time.Hour),
		notAfter:       now.Add(24 * time.Hour),
		keyUsage:       x509.KeyUsageDigitalSignature,
		extKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		emailAddresses: []string{"user@example.com"},
	}
}

func TestNewMTLSAdapter(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("nil logger returns error", func(t *testing.T) {
		_, err := NewMTLSAdapter(nil, nil)
		if err == nil {
			t.Error("Expected error for nil logger")
		}
		if _, ok := err.(ErrNilLogger); !ok {
			t.Errorf("Expected ErrNilLogger, got %T", err)
		}
	})

	t.Run("nil CA returns error", func(t *testing.T) {
		_, err := NewMTLSAdapter(logger, nil)
		if err == nil {
			t.Error("Expected error for nil CA")
		}
		if _, ok := err.(ErrNilCA); !ok {
			t.Errorf("Expected ErrNilCA, got %T", err)
		}
	})
}

func TestMTLSAdapter_ExtractIdentity(t *testing.T) {
	logger := logging.DefaultLogger()

	// Create a mock adapter without CA for identity extraction tests
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
	}

	t.Run("extract identity from email", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.emailAddresses = []string{"user@example.com"}
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "user@example.com" {
			t.Errorf("ID = %v, want user@example.com", identity.ID)
		}
		if identity.Email != "user@example.com" {
			t.Errorf("Email = %v, want user@example.com", identity.Email)
		}
		if identity.Name != "Test User" {
			t.Errorf("Name = %v, want Test User", identity.Name)
		}
	})

	t.Run("extract identity from CN when no email", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldCN
		opts := defaultTestCertOptions()
		opts.emailAddresses = nil
		opts.commonName = "device-001"
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "device-001" {
			t.Errorf("ID = %v, want device-001", identity.ID)
		}
	})

	t.Run("extract identity from serial number", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldSerialNumber
		opts := defaultTestCertOptions()
		opts.serialNumber = "SN-12345"
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "SN-12345" {
			t.Errorf("ID = %v, want SN-12345", identity.ID)
		}
	})

	t.Run("fallback when primary field empty", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldSerialNumber
		opts := defaultTestCertOptions()
		opts.serialNumber = ""
		opts.emailAddresses = []string{"fallback@example.com"}
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "fallback@example.com" {
			t.Errorf("ID = %v, want fallback@example.com", identity.ID)
		}
	})

	t.Run("fallback to common name", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldSerialNumber
		opts := defaultTestCertOptions()
		opts.serialNumber = ""
		opts.emailAddresses = nil
		opts.commonName = "fallback-cn"
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "fallback-cn" {
			t.Errorf("ID = %v, want fallback-cn", identity.ID)
		}
	})

	t.Run("fallback to subject serial number", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldOrganization
		opts := defaultTestCertOptions()
		opts.organization = nil
		opts.emailAddresses = nil
		opts.commonName = ""
		opts.serialNumber = "subject-serial-123"
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "subject-serial-123" {
			t.Errorf("ID = %v, want subject-serial-123", identity.ID)
		}
	})

	t.Run("fallback to DNS name", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldOrganization
		opts := defaultTestCertOptions()
		opts.organization = nil
		opts.emailAddresses = nil
		opts.commonName = ""
		opts.serialNumber = ""
		opts.dnsNames = []string{"device.example.com"}
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.ID != "device.example.com" {
			t.Errorf("ID = %v, want device.example.com", identity.ID)
		}
	})

	t.Run("nil certificate returns error", func(t *testing.T) {
		_, err := adapter.ExtractIdentity(nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
		if _, ok := err.(ErrNilCertificate); !ok {
			t.Errorf("Expected ErrNilCertificate, got %T", err)
		}
	})

	t.Run("no identity returns error", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldSerialNumber
		opts := defaultTestCertOptions()
		opts.serialNumber = ""
		opts.emailAddresses = nil
		opts.commonName = ""
		opts.dnsNames = nil
		cert := createTestCertificate(t, opts)

		_, err := adapter.ExtractIdentity(cert)
		if err == nil {
			t.Error("Expected error when no identity can be extracted")
		}
		if _, ok := err.(ErrIdentityNotFound); !ok {
			t.Errorf("Expected ErrIdentityNotFound, got %T", err)
		}
	})

	t.Run("extracts additional attributes", func(t *testing.T) {
		adapter.config.IdentityField = IdentityFieldEmail
		opts := defaultTestCertOptions()
		opts.emailAddresses = []string{"user@example.com"}
		opts.organization = []string{"Acme Corp"}
		opts.orgUnit = []string{"Engineering"}
		opts.serialNumber = "subject-serial"
		opts.dnsNames = []string{"example.com", "www.example.com"}
		cert := createTestCertificate(t, opts)

		identity, err := adapter.ExtractIdentity(cert)
		if err != nil {
			t.Fatalf("ExtractIdentity failed: %v", err)
		}

		if identity.Attributes["organization"] != "Acme Corp" {
			t.Errorf("Attributes[organization] = %v, want Acme Corp", identity.Attributes["organization"])
		}
		if identity.Attributes["organizational_unit"] != "Engineering" {
			t.Errorf("Attributes[organizational_unit] = %v, want Engineering", identity.Attributes["organizational_unit"])
		}
		if identity.Attributes["subject_serial"] != "subject-serial" {
			t.Errorf("Attributes[subject_serial] = %v, want subject-serial", identity.Attributes["subject_serial"])
		}
		if identity.Attributes["dns_names"] != "example.com,www.example.com" {
			t.Errorf("Attributes[dns_names] = %v, want example.com,www.example.com", identity.Attributes["dns_names"])
		}
	})
}

func TestMTLSAdapter_ExtractTenant(t *testing.T) {
	logger := logging.DefaultLogger()
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
	}

	t.Run("extract tenant from organization", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.organization = []string{"Acme Corp"}
		cert := createTestCertificate(t, opts)

		tenant, err := adapter.ExtractTenant(cert)
		if err != nil {
			t.Fatalf("ExtractTenant failed: %v", err)
		}

		if tenant != "Acme Corp" {
			t.Errorf("tenant = %v, want Acme Corp", tenant)
		}
	})

	t.Run("extract tenant from CN", func(t *testing.T) {
		adapter.config.TenantField = IdentityFieldCN
		opts := defaultTestCertOptions()
		opts.commonName = "tenant-123"
		cert := createTestCertificate(t, opts)

		tenant, err := adapter.ExtractTenant(cert)
		if err != nil {
			t.Fatalf("ExtractTenant failed: %v", err)
		}

		if tenant != "tenant-123" {
			t.Errorf("tenant = %v, want tenant-123", tenant)
		}
	})

	t.Run("fallback to organization when primary empty", func(t *testing.T) {
		adapter.config.TenantField = IdentityFieldSerialNumber
		opts := defaultTestCertOptions()
		opts.serialNumber = ""
		opts.organization = []string{"Fallback Org"}
		cert := createTestCertificate(t, opts)

		tenant, err := adapter.ExtractTenant(cert)
		if err != nil {
			t.Fatalf("ExtractTenant failed: %v", err)
		}

		if tenant != "Fallback Org" {
			t.Errorf("tenant = %v, want Fallback Org", tenant)
		}
	})

	t.Run("nil certificate returns error", func(t *testing.T) {
		_, err := adapter.ExtractTenant(nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
	})

	t.Run("no tenant returns error", func(t *testing.T) {
		adapter.config.TenantField = IdentityFieldSerialNumber
		opts := defaultTestCertOptions()
		opts.serialNumber = ""
		opts.organization = nil
		cert := createTestCertificate(t, opts)

		_, err := adapter.ExtractTenant(cert)
		if err == nil {
			t.Error("Expected error when no tenant can be extracted")
		}
		if _, ok := err.(ErrTenantNotFound); !ok {
			t.Errorf("Expected ErrTenantNotFound, got %T", err)
		}
	})
}

func TestMTLSAdapter_ValidateChain(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("empty chain returns error", func(t *testing.T) {
		adapter := &MTLSAdapter{
			logger: logger,
			config: DefaultMTLSConfig(),
		}

		err := adapter.ValidateChain(context.Background(), []*x509.Certificate{})
		if err == nil {
			t.Error("Expected error for empty chain")
		}
	})

	t.Run("self-signed cert validates against itself", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.isCA = true
		cert := createTestCertificate(t, opts)

		roots := x509.NewCertPool()
		roots.AddCert(cert)

		adapter := &MTLSAdapter{
			logger: logger,
			config: &MTLSConfig{
				TrustedRoots: roots,
			},
		}

		err := adapter.ValidateChain(context.Background(), []*x509.Certificate{cert})
		if err != nil {
			t.Errorf("ValidateChain failed: %v", err)
		}
	})

	t.Run("chain validation fails for untrusted cert", func(t *testing.T) {
		opts := defaultTestCertOptions()
		cert := createTestCertificate(t, opts)

		// Create a different root that doesn't sign this cert
		rootOpts := defaultTestCertOptions()
		rootOpts.isCA = true
		rootOpts.commonName = "Different Root"
		rootCert := createTestCertificate(t, rootOpts)

		roots := x509.NewCertPool()
		roots.AddCert(rootCert)

		adapter := &MTLSAdapter{
			logger: logger,
			config: &MTLSConfig{
				TrustedRoots: roots,
			},
		}

		err := adapter.ValidateChain(context.Background(), []*x509.Certificate{cert})
		if err == nil {
			t.Error("Expected error for untrusted certificate")
		}
	})
}

func TestMTLSAdapter_Authenticate(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("nil certificate returns error", func(t *testing.T) {
		adapter := &MTLSAdapter{
			logger: logger,
			config: DefaultMTLSConfig(),
		}

		_, err := adapter.Authenticate(context.Background(), nil)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}
		if _, ok := err.(ErrNilCertificate); !ok {
			t.Errorf("Expected ErrNilCertificate, got %T", err)
		}
	})

	t.Run("expired certificate returns error", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.notAfter = time.Now().Add(-1 * time.Hour)
		cert := createTestCertificate(t, opts)

		adapter := &MTLSAdapter{
			logger: logger,
			config: DefaultMTLSConfig(),
		}

		_, err := adapter.Authenticate(context.Background(), cert)
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

		adapter := &MTLSAdapter{
			logger: logger,
			config: DefaultMTLSConfig(),
		}

		_, err := adapter.Authenticate(context.Background(), cert)
		if err == nil {
			t.Error("Expected error for not yet valid certificate")
		}
	})

	t.Run("uses default tenant when extraction fails", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.organization = nil
		cert := createTestCertificate(t, opts)

		config := DefaultMTLSConfig()
		config.DefaultTenant = "default-tenant"
		config.TenantField = IdentityFieldSerialNumber
		config.TrustedRoots = selfRoots(cert)

		adapter := &MTLSAdapter{
			logger: logger,
			config: config,
		}

		identity, err := adapter.Authenticate(context.Background(), cert)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}

		if identity.TenantID != "default-tenant" {
			t.Errorf("TenantID = %v, want default-tenant", identity.TenantID)
		}
	})

	t.Run("fails when no tenant and no default", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.organization = nil
		opts.serialNumber = ""
		cert := createTestCertificate(t, opts)

		config := DefaultMTLSConfig()
		config.DefaultTenant = ""
		config.TenantField = IdentityFieldSerialNumber
		config.TrustedRoots = selfRoots(cert)

		adapter := &MTLSAdapter{
			logger: logger,
			config: config,
		}

		_, err := adapter.Authenticate(context.Background(), cert)
		if err == nil {
			t.Error("Expected error when no tenant available")
		}
	})

	t.Run("successful authentication", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.emailAddresses = []string{"user@acme.com"}
		opts.organization = []string{"Acme Corp"}
		cert := createTestCertificate(t, opts)

		config := DefaultMTLSConfig()
		config.TrustedRoots = selfRoots(cert)
		adapter := &MTLSAdapter{
			logger: logger,
			config: config,
		}

		identity, err := adapter.Authenticate(context.Background(), cert)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}

		if identity.ID != "user@acme.com" {
			t.Errorf("ID = %v, want user@acme.com", identity.ID)
		}
		if identity.TenantID != "Acme Corp" {
			t.Errorf("TenantID = %v, want Acme Corp", identity.TenantID)
		}
		if identity.Email != "user@acme.com" {
			t.Errorf("Email = %v, want user@acme.com", identity.Email)
		}
		if identity.CertFingerprint == "" {
			t.Error("CertFingerprint should not be empty")
		}
	})

	t.Run("authentication with IDevID validation", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.emailAddresses = []string{"device@example.com"}
		opts.organization = []string{"Device Org"}
		cert := createTestCertificate(t, opts)

		config := DefaultMTLSConfig()
		config.ValidateIDevID = true
		config.TrustedRoots = selfRoots(cert)

		adapter := &MTLSAdapter{
			logger: logger,
			config: config,
		}

		// Should still succeed even if IDevID validation fails (logged as debug)
		identity, err := adapter.Authenticate(context.Background(), cert)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}

		if identity.ID != "device@example.com" {
			t.Errorf("ID = %v, want device@example.com", identity.ID)
		}
	})

	t.Run("authentication with trusted roots validation", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.isCA = true
		opts.emailAddresses = []string{"user@trusted.com"}
		opts.organization = []string{"Trusted Org"}
		cert := createTestCertificate(t, opts)

		roots := x509.NewCertPool()
		roots.AddCert(cert)

		config := DefaultMTLSConfig()
		config.TrustedRoots = roots

		adapter := &MTLSAdapter{
			logger: logger,
			config: config,
		}

		identity, err := adapter.Authenticate(context.Background(), cert)
		if err != nil {
			t.Fatalf("Authenticate failed: %v", err)
		}

		if identity.ID != "user@trusted.com" {
			t.Errorf("ID = %v, want user@trusted.com", identity.ID)
		}
	})

	t.Run("authentication fails with untrusted roots", func(t *testing.T) {
		opts := defaultTestCertOptions()
		opts.emailAddresses = []string{"user@untrusted.com"}
		opts.organization = []string{"Untrusted Org"}
		cert := createTestCertificate(t, opts)

		// Create different root
		rootOpts := defaultTestCertOptions()
		rootOpts.isCA = true
		rootOpts.commonName = "Different Root"
		rootCert := createTestCertificate(t, rootOpts)

		roots := x509.NewCertPool()
		roots.AddCert(rootCert)

		config := DefaultMTLSConfig()
		config.TrustedRoots = roots

		adapter := &MTLSAdapter{
			logger: logger,
			config: config,
		}

		_, err := adapter.Authenticate(context.Background(), cert)
		if err == nil {
			t.Error("Expected error for untrusted certificate")
		}
	})
}

func TestComputeFingerprint(t *testing.T) {
	opts := defaultTestCertOptions()
	cert := createTestCertificate(t, opts)

	fingerprint := computeFingerprint(cert)

	if fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	if len(fingerprint) != 64 { // SHA256 hex is 64 characters
		t.Errorf("Fingerprint length = %d, want 64", len(fingerprint))
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abcd", "AB:CD"},
		{"abcdef", "AB:CD:EF"},
		{"a", "A"},
		{"ab", "AB"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := formatFingerprint(tt.input)
			if got != tt.expected {
				t.Errorf("formatFingerprint(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMTLSAdapter_Config(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultMTLSConfig()
	config.DefaultTenant = "test-tenant"

	adapter := &MTLSAdapter{
		logger: logger,
		config: config,
	}

	got := adapter.Config()
	if got.DefaultTenant != "test-tenant" {
		t.Errorf("Config().DefaultTenant = %v, want test-tenant", got.DefaultTenant)
	}
}

func TestMTLSAdapter_SetTrustedRoots(t *testing.T) {
	logger := logging.DefaultLogger()
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
	}

	if adapter.config.TrustedRoots != nil {
		t.Error("TrustedRoots should be nil initially")
	}

	roots := x509.NewCertPool()
	adapter.SetTrustedRoots(roots)

	if adapter.config.TrustedRoots != roots {
		t.Error("SetTrustedRoots did not update TrustedRoots")
	}
}

func TestMTLSAdapter_String(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &MTLSConfig{
		IdentityField:     IdentityFieldEmail,
		TenantField:       IdentityFieldOrganization,
		RequireRevocation: true,
		ValidateIDevID:    true,
	}

	adapter := &MTLSAdapter{
		logger: logger,
		config: config,
	}

	str := adapter.String()
	if str == "" {
		t.Error("String() should not return empty string")
	}
	if !contains(str, "email") {
		t.Error("String() should contain identity field")
	}
	if !contains(str, "organization") {
		t.Error("String() should contain tenant field")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestMTLSAdapter_ExtractFromField(t *testing.T) {
	logger := logging.DefaultLogger()
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
	}

	opts := defaultTestCertOptions()
	opts.emailAddresses = []string{"user@example.com"}
	opts.commonName = "Test User"
	opts.serialNumber = "SN123"
	opts.organization = []string{"Test Org"}
	cert := createTestCertificate(t, opts)

	tests := []struct {
		field    IdentityField
		expected string
	}{
		{IdentityFieldEmail, "user@example.com"},
		{IdentityFieldCN, "Test User"},
		{IdentityFieldSerialNumber, "SN123"},
		{IdentityFieldOrganization, "Test Org"},
	}

	for _, tt := range tests {
		t.Run(tt.field.String(), func(t *testing.T) {
			got := adapter.extractFromField(cert, tt.field)
			if got != tt.expected {
				t.Errorf("extractFromField(%v) = %v, want %v", tt.field, got, tt.expected)
			}
		})
	}
}

func TestMTLSAdapter_ExtractFromField_SubjectDN(t *testing.T) {
	logger := logging.DefaultLogger()
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
	}

	opts := defaultTestCertOptions()
	opts.commonName = "Test User"
	opts.organization = []string{"Test Org"}
	cert := createTestCertificate(t, opts)

	got := adapter.extractFromField(cert, IdentityFieldSubjectDN)
	if got == "" {
		t.Error("Subject DN should not be empty")
	}
}

func TestMTLSAdapter_ExtractFromField_EmptyFields(t *testing.T) {
	logger := logging.DefaultLogger()
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
	}

	opts := defaultTestCertOptions()
	opts.emailAddresses = nil
	opts.commonName = ""
	opts.serialNumber = ""
	opts.organization = nil
	cert := createTestCertificate(t, opts)

	t.Run("empty email", func(t *testing.T) {
		got := adapter.extractFromField(cert, IdentityFieldEmail)
		if got != "" {
			t.Errorf("extractFromField(IdentityFieldEmail) = %v, want empty", got)
		}
	})

	t.Run("empty organization", func(t *testing.T) {
		got := adapter.extractFromField(cert, IdentityFieldOrganization)
		if got != "" {
			t.Errorf("extractFromField(IdentityFieldOrganization) = %v, want empty", got)
		}
	})
}

func TestMTLSAdapter_CheckRevocation_NilCA(t *testing.T) {
	logger := logging.DefaultLogger()
	adapter := &MTLSAdapter{
		logger: logger,
		config: DefaultMTLSConfig(),
		ca:     nil,
	}

	opts := defaultTestCertOptions()
	cert := createTestCertificate(t, opts)

	// checkRevocation should return nil when CA is nil
	err := adapter.checkRevocation(context.Background(), cert)
	if err != nil {
		t.Errorf("checkRevocation should return nil for nil CA, got %v", err)
	}
}

func TestNewMTLSAdapterFromRoots(t *testing.T) {
	logger := logging.DefaultLogger()
	roots := x509.NewCertPool()
	roots.AddCert(createTestCertificate(t, testCertOptions{
		commonName: "roots-test-ca",
		isCA:       true,
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(time.Hour),
	}))

	t.Run("success", func(t *testing.T) {
		adapter, err := NewMTLSAdapterFromRoots(logger, roots)
		if err != nil {
			t.Fatalf("NewMTLSAdapterFromRoots: %v", err)
		}
		if adapter.Config().TrustedRoots != roots {
			t.Fatal("trusted roots not applied")
		}
	})

	t.Run("options applied", func(t *testing.T) {
		adapter, err := NewMTLSAdapterFromRoots(logger, roots,
			WithIdentityField(IdentityFieldCN),
			WithDefaultTenant("default"),
		)
		if err != nil {
			t.Fatalf("NewMTLSAdapterFromRoots: %v", err)
		}
		if adapter.Config().IdentityField != IdentityFieldCN {
			t.Fatalf("IdentityField = %v, want CN", adapter.Config().IdentityField)
		}
		if adapter.Config().DefaultTenant != "default" {
			t.Fatalf("DefaultTenant = %q", adapter.Config().DefaultTenant)
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		if _, err := NewMTLSAdapterFromRoots(nil, roots); err == nil {
			t.Fatal("expected ErrNilLogger")
		} else if _, ok := err.(ErrNilLogger); !ok {
			t.Fatalf("err = %v, want ErrNilLogger", err)
		}
	})

	t.Run("nil roots", func(t *testing.T) {
		if _, err := NewMTLSAdapterFromRoots(logger, nil); err == nil {
			t.Fatal("expected ErrMissingTrustedRoots")
		} else if _, ok := err.(ErrMissingTrustedRoots); !ok {
			t.Fatalf("err = %v, want ErrMissingTrustedRoots", err)
		}
	})

	t.Run("revocation rejected", func(t *testing.T) {
		_, err := NewMTLSAdapterFromRoots(logger, roots,
			WithRequireRevocation("https://crl.example.com"))
		if err == nil {
			t.Fatal("expected ErrRevocationRequiresCA")
		}
		if _, ok := err.(ErrRevocationRequiresCA); !ok {
			t.Fatalf("err = %v, want ErrRevocationRequiresCA", err)
		}
	})
}

func TestMTLSAdapterFromRoots_Authenticate(t *testing.T) {
	logger := logging.DefaultLogger()

	// Untrusted self-signed leaf: chain validation must fail against an
	// unrelated root pool.
	unrelated := x509.NewCertPool()
	unrelated.AddCert(createTestCertificate(t, testCertOptions{
		commonName: "unrelated-ca",
		isCA:       true,
		notBefore:  time.Now().Add(-time.Hour),
		notAfter:   time.Now().Add(time.Hour),
	}))
	adapter, err := NewMTLSAdapterFromRoots(logger, unrelated, WithIdentityField(IdentityFieldCN))
	if err != nil {
		t.Fatalf("NewMTLSAdapterFromRoots: %v", err)
	}

	leaf := createTestCertificate(t, testCertOptions{
		commonName:  "client-1",
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(time.Hour),
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if _, err := adapter.Authenticate(context.Background(), leaf); err == nil {
		t.Fatal("untrusted certificate must fail authentication")
	}

	// A self-signed leaf trusted directly as a root authenticates.
	self := x509.NewCertPool()
	self.AddCert(leaf)
	trusted, err := NewMTLSAdapterFromRoots(logger, self,
		WithIdentityField(IdentityFieldCN), WithDefaultTenant("default"))
	if err != nil {
		t.Fatalf("NewMTLSAdapterFromRoots: %v", err)
	}
	ident, err := trusted.Authenticate(context.Background(), leaf)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ident.ID != "client-1" {
		t.Fatalf("ID = %q, want client-1", ident.ID)
	}
	if ident.TenantID != "default" {
		t.Fatalf("TenantID = %q, want default", ident.TenantID)
	}
}

// selfRoots returns a pool that trusts the given self-signed certificate.
func selfRoots(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// verifyErrCA is a CA whose Verify always fails with err; every other
// method panics through the nil embedded interface.
type verifyErrCA struct {
	quicbaasca.CACertificateAuthority
	err error
}

func (c verifyErrCA) Verify(*x509.Certificate, ...crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, c.err
}

// errVerifyUnavailable is a non-revocation failure from the CA.
type errVerifyUnavailable struct{}

func (errVerifyUnavailable) Error() string { return "ca: certificate store unavailable" }

func TestAuthenticate_NilTrustedRoots_FailsClosed(t *testing.T) {
	cert := createTestCertificate(t, defaultTestCertOptions())
	adapter := &MTLSAdapter{
		logger: logging.DefaultLogger(),
		config: DefaultMTLSConfig(),
	}
	if adapter.config.TrustedRoots != nil {
		t.Fatal("precondition: TrustedRoots must be nil")
	}

	identity, err := adapter.Authenticate(context.Background(), cert)
	if err == nil {
		t.Fatalf("Authenticate with nil TrustedRoots returned identity %+v, want error", identity)
	}
	if !errors.As(err, new(ErrMissingTrustedRoots)) {
		t.Fatalf("err = %T %v, want ErrMissingTrustedRoots", err, err)
	}
	if identity != nil {
		t.Fatalf("identity = %+v, want nil", identity)
	}
}

func TestCheckRevocation_NonRevocationError_FailsClosed(t *testing.T) {
	cert := createTestCertificate(t, defaultTestCertOptions())
	cause := errVerifyUnavailable{}
	adapter := &MTLSAdapter{
		logger: logging.DefaultLogger(),
		ca:     verifyErrCA{err: cause},
		config: DefaultMTLSConfig(),
	}

	err := adapter.checkRevocation(context.Background(), cert)
	if err == nil {
		t.Fatal("checkRevocation returned nil for a failed CA Verify, want error")
	}
	if !errors.As(err, new(ErrRevocationCheckFailed)) {
		t.Fatalf("err = %T %v, want ErrRevocationCheckFailed", err, err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v does not wrap the CA error", err)
	}
	if errors.As(err, new(ErrCertificateRevoked)) {
		t.Fatalf("err = %v, a non-revocation failure must not read as revoked", err)
	}
}

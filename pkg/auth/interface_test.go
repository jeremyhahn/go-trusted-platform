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
	"crypto/x509"
	"testing"
	"time"
)

func TestIdentityField_String(t *testing.T) {
	tests := []struct {
		field    IdentityField
		expected string
	}{
		{IdentityFieldEmail, "email"},
		{IdentityFieldCN, "cn"},
		{IdentityFieldSerialNumber, "serial_number"},
		{IdentityFieldSubjectDN, "subject_dn"},
		{IdentityFieldOrganization, "organization"},
		{IdentityField(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.field.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIdentity_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		expiry   time.Time
		expected bool
	}{
		{
			name:     "not expired",
			expiry:   time.Now().Add(24 * time.Hour),
			expected: false,
		},
		{
			name:     "expired",
			expiry:   time.Now().Add(-24 * time.Hour),
			expected: true,
		},
		{
			name:     "just expired",
			expiry:   time.Now().Add(-1 * time.Second),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{CertExpiry: tt.expiry}
			if got := identity.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIdentity_TimeUntilExpiry(t *testing.T) {
	// Test with future expiry
	futureExpiry := time.Now().Add(24 * time.Hour)
	identity := &Identity{CertExpiry: futureExpiry}
	remaining := identity.TimeUntilExpiry()

	// Should be approximately 24 hours (allowing for small timing differences)
	if remaining < 23*time.Hour || remaining > 25*time.Hour {
		t.Errorf("TimeUntilExpiry() = %v, expected approximately 24 hours", remaining)
	}

	// Test with past expiry
	pastExpiry := time.Now().Add(-24 * time.Hour)
	identity = &Identity{CertExpiry: pastExpiry}
	remaining = identity.TimeUntilExpiry()

	if remaining > 0 {
		t.Errorf("TimeUntilExpiry() should be negative for expired cert, got %v", remaining)
	}
}

func TestWithTrustedRoots(t *testing.T) {
	roots := x509.NewCertPool()
	config := &MTLSConfig{}

	WithTrustedRoots(roots)(config)

	if config.TrustedRoots != roots {
		t.Error("WithTrustedRoots did not set TrustedRoots")
	}
}

func TestWithRequireRevocation(t *testing.T) {
	endpoint := "https://example.com/crl"
	config := &MTLSConfig{}

	WithRequireRevocation(endpoint)(config)

	if !config.RequireRevocation {
		t.Error("WithRequireRevocation did not set RequireRevocation to true")
	}
	if config.RevocationEndpoint != endpoint {
		t.Errorf("WithRequireRevocation set endpoint to %v, want %v", config.RevocationEndpoint, endpoint)
	}
}

func TestWithIdentityField(t *testing.T) {
	config := &MTLSConfig{}

	WithIdentityField(IdentityFieldCN)(config)

	if config.IdentityField != IdentityFieldCN {
		t.Errorf("WithIdentityField set field to %v, want %v", config.IdentityField, IdentityFieldCN)
	}
}

func TestWithTenantField(t *testing.T) {
	config := &MTLSConfig{}

	WithTenantField(IdentityFieldOrganization)(config)

	if config.TenantField != IdentityFieldOrganization {
		t.Errorf("WithTenantField set field to %v, want %v", config.TenantField, IdentityFieldOrganization)
	}
}

func TestWithDefaultTenant(t *testing.T) {
	tenant := "test-tenant"
	config := &MTLSConfig{}

	WithDefaultTenant(tenant)(config)

	if config.DefaultTenant != tenant {
		t.Errorf("WithDefaultTenant set tenant to %v, want %v", config.DefaultTenant, tenant)
	}
}

func TestWithIDevIDValidation(t *testing.T) {
	config := &MTLSConfig{}

	WithIDevIDValidation(true)(config)

	if !config.ValidateIDevID {
		t.Error("WithIDevIDValidation did not set ValidateIDevID to true")
	}

	WithIDevIDValidation(false)(config)

	if config.ValidateIDevID {
		t.Error("WithIDevIDValidation did not set ValidateIDevID to false")
	}
}

func TestWithRequireClientAuth(t *testing.T) {
	config := &MTLSConfig{}

	WithRequireClientAuth(true)(config)

	if !config.RequireClientAuth {
		t.Error("WithRequireClientAuth did not set RequireClientAuth to true")
	}
}

func TestDefaultMTLSConfig(t *testing.T) {
	config := DefaultMTLSConfig()

	if config.IdentityField != IdentityFieldEmail {
		t.Errorf("DefaultMTLSConfig IdentityField = %v, want %v", config.IdentityField, IdentityFieldEmail)
	}
	if config.TenantField != IdentityFieldOrganization {
		t.Errorf("DefaultMTLSConfig TenantField = %v, want %v", config.TenantField, IdentityFieldOrganization)
	}
	if !config.RequireClientAuth {
		t.Error("DefaultMTLSConfig RequireClientAuth should be true")
	}
	if config.TrustedRoots != nil {
		t.Error("DefaultMTLSConfig TrustedRoots should be nil")
	}
}

func TestMTLSConfig_MultipleOptions(t *testing.T) {
	roots := x509.NewCertPool()
	config := DefaultMTLSConfig()

	// Apply multiple options
	opts := []MTLSOption{
		WithTrustedRoots(roots),
		WithIdentityField(IdentityFieldCN),
		WithTenantField(IdentityFieldSerialNumber),
		WithDefaultTenant("default-org"),
		WithIDevIDValidation(true),
		WithRequireRevocation("https://crl.example.com"),
	}

	for _, opt := range opts {
		opt(config)
	}

	if config.TrustedRoots != roots {
		t.Error("TrustedRoots not set correctly")
	}
	if config.IdentityField != IdentityFieldCN {
		t.Error("IdentityField not set correctly")
	}
	if config.TenantField != IdentityFieldSerialNumber {
		t.Error("TenantField not set correctly")
	}
	if config.DefaultTenant != "default-org" {
		t.Error("DefaultTenant not set correctly")
	}
	if !config.ValidateIDevID {
		t.Error("ValidateIDevID not set correctly")
	}
	if !config.RequireRevocation {
		t.Error("RequireRevocation not set correctly")
	}
	if config.RevocationEndpoint != "https://crl.example.com" {
		t.Error("RevocationEndpoint not set correctly")
	}
}

func TestIdentity_WithAttributes(t *testing.T) {
	identity := &Identity{
		ID:              "user@example.com",
		TenantID:        "example.com",
		Email:           "user@example.com",
		Name:            "Test User",
		CertFingerprint: "abc123",
		CertExpiry:      time.Now().Add(365 * 24 * time.Hour),
		IssuedAt:        time.Now(),
		Issuer:          "Test CA",
		SerialNumber:    "123456",
		Attributes: map[string]string{
			"department": "Engineering",
			"role":       "Developer",
		},
	}

	// Verify all fields are set correctly
	if identity.ID != "user@example.com" {
		t.Errorf("ID = %v, want user@example.com", identity.ID)
	}
	if identity.TenantID != "example.com" {
		t.Errorf("TenantID = %v, want example.com", identity.TenantID)
	}
	if identity.Attributes["department"] != "Engineering" {
		t.Errorf("Attributes[department] = %v, want Engineering", identity.Attributes["department"])
	}
	if identity.Attributes["role"] != "Developer" {
		t.Errorf("Attributes[role] = %v, want Developer", identity.Attributes["role"])
	}
}

func TestIdentityFieldConstants(t *testing.T) {
	// Verify the constants have expected values
	if IdentityFieldEmail != 0 {
		t.Errorf("IdentityFieldEmail = %v, want 0", IdentityFieldEmail)
	}
	if IdentityFieldCN != 1 {
		t.Errorf("IdentityFieldCN = %v, want 1", IdentityFieldCN)
	}
	if IdentityFieldSerialNumber != 2 {
		t.Errorf("IdentityFieldSerialNumber = %v, want 2", IdentityFieldSerialNumber)
	}
	if IdentityFieldSubjectDN != 3 {
		t.Errorf("IdentityFieldSubjectDN = %v, want 3", IdentityFieldSubjectDN)
	}
	if IdentityFieldOrganization != 4 {
		t.Errorf("IdentityFieldOrganization = %v, want 4", IdentityFieldOrganization)
	}
}

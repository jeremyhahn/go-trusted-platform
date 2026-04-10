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
	"crypto/x509"
	"time"
)

// IdentityField defines which certificate field to extract identity from.
type IdentityField int

const (
	// IdentityFieldEmail extracts identity from email SAN.
	IdentityFieldEmail IdentityField = iota
	// IdentityFieldCN extracts identity from Common Name.
	IdentityFieldCN
	// IdentityFieldSerialNumber extracts identity from Serial Number.
	IdentityFieldSerialNumber
	// IdentityFieldSubjectDN extracts identity from full Subject DN.
	IdentityFieldSubjectDN
	// IdentityFieldOrganization extracts identity from Organization.
	IdentityFieldOrganization
)

// String returns a human-readable representation of the IdentityField.
func (f IdentityField) String() string {
	switch f {
	case IdentityFieldEmail:
		return "email"
	case IdentityFieldCN:
		return "cn"
	case IdentityFieldSerialNumber:
		return "serial_number"
	case IdentityFieldSubjectDN:
		return "subject_dn"
	case IdentityFieldOrganization:
		return "organization"
	default:
		return "unknown"
	}
}

// Identity represents an authenticated identity extracted from a certificate.
type Identity struct {
	// ID is the primary identifier extracted from the certificate.
	ID string

	// TenantID is the organization or tenant identifier.
	TenantID string

	// UserID is the IAM user ID after lookup (may be empty before IAM resolution).
	UserID string

	// Email is the email address from the certificate.
	Email string

	// Name is the display name (typically Common Name).
	Name string

	// CertFingerprint is the SHA256 fingerprint of the certificate.
	CertFingerprint string

	// CertExpiry is when the certificate expires.
	CertExpiry time.Time

	// IssuedAt is when the certificate was issued.
	IssuedAt time.Time

	// Issuer is the issuer's Common Name.
	Issuer string

	// SerialNumber is the certificate's serial number in hex format.
	SerialNumber string

	// Attributes contains additional extracted attributes.
	Attributes map[string]string
}

// IsExpired returns true if the certificate has expired.
func (i *Identity) IsExpired() bool {
	return time.Now().After(i.CertExpiry)
}

// TimeUntilExpiry returns the duration until the certificate expires.
func (i *Identity) TimeUntilExpiry() time.Duration {
	return time.Until(i.CertExpiry)
}

// Authenticator provides mTLS-based authentication.
type Authenticator interface {
	// Authenticate validates a client certificate and extracts identity.
	// Returns an Identity on success, or an error if authentication fails.
	Authenticate(ctx context.Context, clientCert *x509.Certificate) (*Identity, error)

	// ValidateChain validates a certificate chain against trusted roots.
	// The first certificate should be the leaf, followed by intermediates.
	ValidateChain(ctx context.Context, certs []*x509.Certificate) error

	// ExtractIdentity extracts identity information from a certificate.
	// This does not perform chain validation.
	ExtractIdentity(cert *x509.Certificate) (*Identity, error)

	// ExtractTenant extracts the tenant identifier from a certificate.
	ExtractTenant(cert *x509.Certificate) (string, error)
}

// MTLSConfig holds configuration for the mTLS adapter.
type MTLSConfig struct {
	// TrustedRoots is the certificate pool of trusted root CAs.
	TrustedRoots *x509.CertPool

	// RequireRevocation enables CRL-based revocation checking.
	RequireRevocation bool

	// RevocationEndpoint is the URL for revocation checking (if RequireRevocation is true).
	RevocationEndpoint string

	// IdentityField specifies which certificate field to extract identity from.
	IdentityField IdentityField

	// TenantField specifies which certificate field to extract tenant from.
	TenantField IdentityField

	// DefaultTenant is used when no tenant can be extracted from the certificate.
	DefaultTenant string

	// ValidateIDevID enables additional validation for IDevID certificates.
	ValidateIDevID bool

	// RequireClientAuth requires client certificate authentication.
	RequireClientAuth bool
}

// MTLSOption is a functional option for configuring MTLSConfig.
type MTLSOption func(*MTLSConfig)

// WithTrustedRoots sets the trusted root certificate pool.
func WithTrustedRoots(roots *x509.CertPool) MTLSOption {
	return func(c *MTLSConfig) {
		c.TrustedRoots = roots
	}
}

// WithRequireRevocation enables revocation checking with the specified endpoint.
func WithRequireRevocation(endpoint string) MTLSOption {
	return func(c *MTLSConfig) {
		c.RequireRevocation = true
		c.RevocationEndpoint = endpoint
	}
}

// WithIdentityField sets which certificate field to extract identity from.
func WithIdentityField(field IdentityField) MTLSOption {
	return func(c *MTLSConfig) {
		c.IdentityField = field
	}
}

// WithTenantField sets which certificate field to extract tenant from.
func WithTenantField(field IdentityField) MTLSOption {
	return func(c *MTLSConfig) {
		c.TenantField = field
	}
}

// WithDefaultTenant sets the default tenant when none can be extracted.
func WithDefaultTenant(tenant string) MTLSOption {
	return func(c *MTLSConfig) {
		c.DefaultTenant = tenant
	}
}

// WithIDevIDValidation enables IDevID certificate validation.
func WithIDevIDValidation(enabled bool) MTLSOption {
	return func(c *MTLSConfig) {
		c.ValidateIDevID = enabled
	}
}

// WithRequireClientAuth sets whether client certificates are required.
func WithRequireClientAuth(required bool) MTLSOption {
	return func(c *MTLSConfig) {
		c.RequireClientAuth = required
	}
}

// DefaultMTLSConfig returns a default MTLSConfig with sensible defaults.
func DefaultMTLSConfig() *MTLSConfig {
	return &MTLSConfig{
		IdentityField:     IdentityFieldEmail,
		TenantField:       IdentityFieldOrganization,
		RequireClientAuth: true,
	}
}

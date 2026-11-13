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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// MTLSAdapter implements the Authenticator interface using mTLS certificates.
type MTLSAdapter struct {
	logger *logging.Logger
	ca     quicbaasca.CACertificateAuthority
	config *MTLSConfig
}

// NewMTLSAdapter creates a new MTLSAdapter with the provided configuration.
func NewMTLSAdapter(
	logger *logging.Logger,
	ca quicbaasca.CACertificateAuthority,
	opts ...MTLSOption,
) (*MTLSAdapter, error) {

	if logger == nil {
		return nil, ErrNilLogger{}
	}
	if ca == nil {
		return nil, ErrNilCA{}
	}

	config := DefaultMTLSConfig()
	for _, opt := range opts {
		opt(config)
	}

	// If no trusted roots provided, try to get them from the CA
	if config.TrustedRoots == nil {
		pool, err := ca.CABundleCertPool()
		if err != nil {
			logger.Warnf("auth: failed to get CA bundle cert pool: %v", err)
		} else {
			config.TrustedRoots = pool
		}
	}

	return &MTLSAdapter{
		logger: logger,
		ca:     ca,
		config: config,
	}, nil
}

// Authenticate validates a client certificate and extracts identity information.
func (m *MTLSAdapter) Authenticate(ctx context.Context, cert *x509.Certificate) (*Identity, error) {
	if cert == nil {
		return nil, ErrNilCertificate{}
	}

	// Check certificate expiry
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, ErrCertificateInvalid{Reason: "certificate not yet valid"}
	}
	if now.After(cert.NotAfter) {
		return nil, ErrCertificateExpired{}
	}

	// Validate against trusted roots. Without roots the chain cannot be
	// verified, so authentication fails closed.
	if m.config.TrustedRoots == nil {
		return nil, ErrMissingTrustedRoots{}
	}
	if err := m.validateCertificate(ctx, cert); err != nil {
		return nil, err
	}

	// Check revocation if enabled
	if m.config.RequireRevocation {
		if err := m.checkRevocation(ctx, cert); err != nil {
			return nil, err
		}
	}

	// Validate IDevID if enabled
	if m.config.ValidateIDevID {
		if err := ValidateIDevID(ctx, cert); err != nil {
			m.logger.Debugf("auth: IDevID validation failed: %v", err)
			// Continue - might not be an IDevID certificate
		}
	}

	// Extract identity
	identity, err := m.ExtractIdentity(cert)
	if err != nil {
		return nil, err
	}

	// Extract tenant
	tenantID, err := m.ExtractTenant(cert)
	if err != nil {
		// Use default tenant if available
		if m.config.DefaultTenant != "" {
			tenantID = m.config.DefaultTenant
		} else {
			return nil, err
		}
	}
	identity.TenantID = tenantID

	m.logger.Debugf("auth: authenticated identity %s for tenant %s", identity.ID, identity.TenantID)

	return identity, nil
}

// ValidateChain validates a certificate chain against trusted roots.
func (m *MTLSAdapter) ValidateChain(ctx context.Context, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return ErrCertificateInvalid{Reason: "empty certificate chain"}
	}

	leaf := certs[0]

	// Build intermediate pool from chain
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verify options
	opts := x509.VerifyOptions{
		Roots:         m.config.TrustedRoots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   time.Now(),
	}

	if _, err := leaf.Verify(opts); err != nil {
		return ErrChainValidationFailed{Cause: err}
	}

	return nil
}

// ExtractIdentity extracts identity information from a certificate.
func (m *MTLSAdapter) ExtractIdentity(cert *x509.Certificate) (*Identity, error) {
	if cert == nil {
		return nil, ErrNilCertificate{}
	}

	// Extract primary identifier
	id := m.extractFromField(cert, m.config.IdentityField)
	if id == "" {
		// Fallback to other fields
		id = m.extractFallbackIdentity(cert)
		if id == "" {
			return nil, ErrIdentityNotFound{}
		}
	}

	// Extract email if available
	var email string
	if len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	}

	// Build identity
	identity := &Identity{
		ID:              id,
		Email:           email,
		Name:            cert.Subject.CommonName,
		CertFingerprint: computeFingerprint(cert),
		CertExpiry:      cert.NotAfter,
		IssuedAt:        cert.NotBefore,
		Issuer:          cert.Issuer.CommonName,
		SerialNumber:    cert.SerialNumber.Text(16),
		Attributes:      make(map[string]string),
	}

	// Add additional attributes
	if cert.Subject.SerialNumber != "" {
		identity.Attributes["subject_serial"] = cert.Subject.SerialNumber
	}
	if len(cert.Subject.Organization) > 0 {
		identity.Attributes["organization"] = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		identity.Attributes["organizational_unit"] = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.DNSNames) > 0 {
		identity.Attributes["dns_names"] = strings.Join(cert.DNSNames, ",")
	}

	return identity, nil
}

// ExtractTenant extracts the tenant identifier from a certificate.
func (m *MTLSAdapter) ExtractTenant(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrNilCertificate{}
	}

	tenant := m.extractFromField(cert, m.config.TenantField)
	if tenant == "" {
		// Fallback: try Organization
		if len(cert.Subject.Organization) > 0 {
			tenant = cert.Subject.Organization[0]
		}
	}

	if tenant == "" {
		return "", ErrTenantNotFound{}
	}

	return tenant, nil
}

// extractFromField extracts a value from the specified certificate field.
func (m *MTLSAdapter) extractFromField(cert *x509.Certificate, field IdentityField) string {
	switch field {
	case IdentityFieldEmail:
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0]
		}
	case IdentityFieldCN:
		return cert.Subject.CommonName
	case IdentityFieldSerialNumber:
		return cert.Subject.SerialNumber
	case IdentityFieldSubjectDN:
		return cert.Subject.String()
	case IdentityFieldOrganization:
		if len(cert.Subject.Organization) > 0 {
			return cert.Subject.Organization[0]
		}
	}
	return ""
}

// extractFallbackIdentity tries multiple fields to find an identity.
func (m *MTLSAdapter) extractFallbackIdentity(cert *x509.Certificate) string {
	// Try email first
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}

	// Try Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Try Serial Number
	if cert.Subject.SerialNumber != "" {
		return cert.Subject.SerialNumber
	}

	// Try first DNS SAN
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	return ""
}

// validateCertificate validates a certificate against the trusted roots.
func (m *MTLSAdapter) validateCertificate(ctx context.Context, cert *x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots:       m.config.TrustedRoots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return ErrChainValidationFailed{Cause: err}
	}

	return nil
}

// checkRevocation checks if the certificate has been revoked.
func (m *MTLSAdapter) checkRevocation(ctx context.Context, cert *x509.Certificate) error {
	// Use the CA's certificate store to check revocation
	if m.ca == nil {
		return nil // No CA configured, skip revocation check
	}

	// Ask the CA directly whether the serial is revoked. CA.Verify is not
	// used here: it verifies for server auth and so rejects valid
	// client-auth-only certificates.
	revoked, err := m.ca.IsRevoked(cert.SerialNumber)
	if err != nil {
		// Revocation status is unknown: fail closed.
		return ErrRevocationCheckFailed{Reason: "certificate authority revocation lookup failed", Err: err}
	}
	if revoked {
		return ErrCertificateRevoked{}
	}

	return nil
}

// computeFingerprint computes the SHA256 fingerprint of a certificate.
func computeFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// formatFingerprint formats a fingerprint with colons for display.
func formatFingerprint(fingerprint string) string {
	var parts []string
	for i := 0; i < len(fingerprint); i += 2 {
		end := i + 2
		if end > len(fingerprint) {
			end = len(fingerprint)
		}
		parts = append(parts, fingerprint[i:end])
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

// Config returns the current MTLSConfig.
func (m *MTLSAdapter) Config() *MTLSConfig {
	return m.config
}

// SetTrustedRoots updates the trusted root certificate pool.
func (m *MTLSAdapter) SetTrustedRoots(roots *x509.CertPool) {
	m.config.TrustedRoots = roots
}

// String returns a string representation of the adapter configuration.
func (m *MTLSAdapter) String() string {
	return fmt.Sprintf(
		"MTLSAdapter{identity_field=%s, tenant_field=%s, revocation=%v, idevid=%v}",
		m.config.IdentityField,
		m.config.TenantField,
		m.config.RequireRevocation,
		m.config.ValidateIDevID,
	)
}

// NewMTLSAdapterFromRoots creates an MTLSAdapter anchored on an explicit
// trusted-root pool instead of a certificate authority. It exists for
// consumers that validate platform-issued client certificates but do not
// host the platform CA in-process (e.g. gatewayd, which sources the CA pool
// through the pkg/trust resolver). Revocation checking requires the CA and
// is rejected with ErrRevocationRequiresCA; identity extraction, chain
// validation, and IDevID validation behave identically to NewMTLSAdapter.
func NewMTLSAdapterFromRoots(
	logger *logging.Logger,
	roots *x509.CertPool,
	opts ...MTLSOption,
) (*MTLSAdapter, error) {

	if logger == nil {
		return nil, ErrNilLogger{}
	}
	if roots == nil {
		return nil, ErrMissingTrustedRoots{}
	}

	config := DefaultMTLSConfig()
	for _, opt := range opts {
		opt(config)
	}
	config.TrustedRoots = roots

	if config.RequireRevocation {
		return nil, ErrRevocationRequiresCA{}
	}

	return &MTLSAdapter{
		logger: logger,
		config: config,
	}, nil
}

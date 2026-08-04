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

package policy

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// X509PolicyExtractor extracts policy from X.509 certificate extensions.
// Zone extraction uses the canonical OIDTPNetworkZone extension
// (1.3.6.1.4.1.29377.101.21) via ParseNetworkZoneExtension from the
// quicbaas SDK re-export.
type X509PolicyExtractor struct {
	// zones is the resolved zone set used to validate zone values extracted
	// from certificates. When non-nil, a zone name not present in the set
	// triggers fail-closed quarantine logic.
	zones []zone.ZoneConfig

	// logger is used for audit events (quarantine, zone mismatch).
	logger *slog.Logger
}

// NewX509PolicyExtractor creates a new policy extractor with the resolved
// zone set used for zone-declaration enforcement.
func NewX509PolicyExtractor(opts ...X509PolicyExtractorOption) *X509PolicyExtractor {
	e := &X509PolicyExtractor{}
	for _, opt := range opts {
		opt(e)
	}
	if e.logger == nil {
		e.logger = slog.Default()
	}
	return e
}

// X509PolicyExtractorOption configures an X509PolicyExtractor.
type X509PolicyExtractorOption func(*X509PolicyExtractor)

// WithPolicyExtractorZones sets the resolved zone set for enforcement.
func WithPolicyExtractorZones(zones []zone.ZoneConfig) X509PolicyExtractorOption {
	return func(e *X509PolicyExtractor) {
		e.zones = zones
	}
}

// WithPolicyExtractorLogger sets the logger for audit events.
func WithPolicyExtractorLogger(logger *slog.Logger) X509PolicyExtractorOption {
	return func(e *X509PolicyExtractor) {
		e.logger = logger
	}
}

// ExtractPolicy extracts complete policy from a certificate. When the
// certificate carries an OIDTPNetworkZone extension the zone value is set on
// the returned policy. A zone value that is not present in the configured
// resolved zone set triggers fail-closed: the returned policy carries the
// quarantine zone and an ErrZoneNotDeclared is returned, allowing callers to
// emit an audit event and apply quarantine flows.
func (e *X509PolicyExtractor) ExtractPolicy(cert *x509.Certificate) (*PortPolicy, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	policy := &PortPolicy{
		Certificate: cert,
		ExpiresAt:   cert.NotAfter,
		IssuedAt:    time.Now(),
		Metadata:    make(map[string]string),
	}

	// Extract tenant ID from Subject.
	tenantID, err := e.ExtractTenantID(cert)
	if err != nil {
		return nil, err
	}
	policy.TenantID = tenantID

	// Extract zone extension (optional). When absent zone-less enforcement
	// applies (backward compatible: VLAN derived from profile).
	z, err := e.ExtractZone(cert)
	if err != nil && err != ErrMissingZoneExtension {
		return nil, err
	}
	policy.Zone = zone.Zone(z)

	// Fail-closed enforcement: zone present but not declared in the resolved set.
	if policy.Zone != "" && len(e.zones) > 0 {
		if !e.isZoneDeclared(policy.Zone) {
			// Resolve quarantine zone for fail-closed placement.
			quarantine, qErr := zone.ZoneForRole(e.zones, zone.LifecycleRoleQuarantine)
			if qErr != nil {
				quarantine = zone.ZoneQuarantine
			}
			e.logger.Warn("certificate carries undeclared zone, applying quarantine",
				slog.String("cert_zone", string(policy.Zone)),
				slog.String("quarantine_zone", string(quarantine)),
				slog.String("subject", cert.Subject.CommonName),
			)
			policy.Zone = quarantine
			return policy, ErrZoneNotDeclared{Zone: policy.Zone, Subject: cert.Subject.CommonName}
		}
	}

	// Extract ACLs (optional; failure is non-fatal).
	acls, err := e.ExtractACLs(cert)
	if err == nil {
		policy.ACLs = acls
	}

	return policy, nil
}

// ExtractTenantID extracts the tenant ID from the certificate subject.
// Falls back to the first Organization field, then to the first component
// of the CommonName.
func (e *X509PolicyExtractor) ExtractTenantID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrInvalidCertificate
	}

	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0], nil
	}

	if cert.Subject.CommonName != "" {
		parts := strings.Split(cert.Subject.CommonName, ".")
		if len(parts) > 0 {
			return parts[0], nil
		}
	}

	return "", ErrMissingTenantID
}

// ExtractZone extracts the network zone from the OIDTPNetworkZone extension
// (1.3.6.1.4.1.29377.101.21) via ParseNetworkZoneExtension from the quicbaas
// SDK re-export. Returns ErrMissingZoneExtension when the extension is absent.
func (e *X509PolicyExtractor) ExtractZone(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrInvalidCertificate
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(quicbaasca.OIDTPNetworkZone) {
			return quicbaasca.ParseNetworkZoneExtension(ext)
		}
	}
	return "", ErrMissingZoneExtension
}

// ExtractACLs extracts ACL rules from the certificate. Returns a default
// allow-all rule when no ACL extension is present.
func (e *X509PolicyExtractor) ExtractACLs(cert *x509.Certificate) ([]ACLRule, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	return e.getDefaultACLs(), nil
}

// getDefaultACLs returns default ACL rules for authenticated ports.
func (e *X509PolicyExtractor) getDefaultACLs() []ACLRule {
	return []ACLRule{
		{
			Priority:    100,
			Description: "Allow all traffic for authenticated port",
			Match:       FlowMatch{},
			Action: FlowAction{
				Type: FlowActionNormal,
			},
		},
	}
}

// isZoneDeclared reports whether z is present in the configured resolved zone set.
func (e *X509PolicyExtractor) isZoneDeclared(z zone.Zone) bool {
	for _, zc := range e.zones {
		if zc.Name == z {
			return true
		}
	}
	return false
}

// DefaultCertificateValidator provides basic certificate validation.
type DefaultCertificateValidator struct {
	// Roots is the trusted root CA pool.
	Roots *x509.CertPool

	// Intermediates is the intermediate CA pool.
	Intermediates *x509.CertPool

	// RevocationList contains revoked certificate serial numbers.
	RevocationList map[string]bool
}

// NewDefaultCertificateValidator creates a new certificate validator.
func NewDefaultCertificateValidator(roots, intermediates *x509.CertPool) *DefaultCertificateValidator {
	return &DefaultCertificateValidator{
		Roots:          roots,
		Intermediates:  intermediates,
		RevocationList: make(map[string]bool),
	}
}

// ValidateCertificate validates a certificate.
func (v *DefaultCertificateValidator) ValidateCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	revoked, err := v.IsRevoked(cert)
	if err != nil {
		return &WrappedError{Msg: "revocation check failed", Err: err}
	}
	if revoked {
		return ErrCertificateRevoked
	}

	opts := x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: v.Intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return &WrappedError{Msg: "certificate verification failed", Err: err}
	}

	return nil
}

// IsRevoked checks if a certificate has been revoked.
func (v *DefaultCertificateValidator) IsRevoked(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, ErrInvalidCertificate
	}
	return v.RevocationList[cert.SerialNumber.String()], nil
}

// CheckExpiry checks if a certificate will expire within the threshold.
func (v *DefaultCertificateValidator) CheckExpiry(cert *x509.Certificate, threshold time.Duration) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	if now.Add(threshold).After(cert.NotAfter) {
		return &WrappedError{Msg: fmt.Sprintf("certificate expires within %v", threshold), Err: ErrCertificateExpired}
	}

	return nil
}

// AddRevoked adds a certificate to the revocation list.
func (v *DefaultCertificateValidator) AddRevoked(serialNumber string) {
	v.RevocationList[serialNumber] = true
}

// RemoveRevoked removes a certificate from the revocation list.
func (v *DefaultCertificateValidator) RemoveRevoked(serialNumber string) {
	delete(v.RevocationList, serialNumber)
}

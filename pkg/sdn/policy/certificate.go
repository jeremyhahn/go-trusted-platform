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
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// X509PolicyExtractor extracts policy from X.509 certificate extensions
type X509PolicyExtractor struct {
	// OIDTenantID is the OID for tenant ID extension
	OIDTenantID asn1.ObjectIdentifier

	// OIDVLAN is the OID for VLAN extension
	OIDVLAN asn1.ObjectIdentifier

	// OIDACLs is the OID for ACL rules extension
	OIDACLs asn1.ObjectIdentifier
}

// NewX509PolicyExtractor creates a new policy extractor with default OIDs
func NewX509PolicyExtractor() *X509PolicyExtractor {
	return &X509PolicyExtractor{
		// These OIDs are examples - adjust based on your certificate schema
		OIDTenantID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}, // Example OID
		OIDVLAN:     asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}, // Example OID
		OIDACLs:     asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}, // Example OID
	}
}

// ExtractPolicy extracts complete policy from a certificate
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

	// Extract tenant ID
	tenantID, err := e.ExtractTenantID(cert)
	if err != nil {
		return nil, err
	}
	policy.TenantID = tenantID

	// Extract VLAN
	vlan, err := e.ExtractVLAN(cert)
	if err != nil {
		return nil, err
	}
	policy.VLAN = vlan

	// Extract ACLs (optional)
	acls, err := e.ExtractACLs(cert)
	if err == nil {
		policy.ACLs = acls
	}

	return policy, nil
}

// ExtractTenantID extracts the tenant ID from certificate
func (e *X509PolicyExtractor) ExtractTenantID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrInvalidCertificate
	}

	// Try to extract from extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(e.OIDTenantID) {
			var tenantID string
			if _, err := asn1.Unmarshal(ext.Value, &tenantID); err == nil {
				return tenantID, nil
			}
		}
	}

	// Fallback: extract from Subject Organization
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0], nil
	}

	// Fallback: extract from Subject Common Name prefix
	if cert.Subject.CommonName != "" {
		parts := strings.Split(cert.Subject.CommonName, ".")
		if len(parts) > 0 {
			return parts[0], nil
		}
	}

	return "", ErrMissingTenantID
}

// ExtractVLAN extracts the VLAN ID from certificate
func (e *X509PolicyExtractor) ExtractVLAN(cert *x509.Certificate) (uint16, error) {
	if cert == nil {
		return 0, ErrInvalidCertificate
	}

	// Try to extract from extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(e.OIDVLAN) {
			var vlan int
			if _, err := asn1.Unmarshal(ext.Value, &vlan); err == nil {
				if vlan < 1 || vlan > 4094 {
					return 0, ErrInvalidVLAN
				}
				return uint16(vlan), nil
			}
		}
	}

	// Fallback: extract from Subject Organizational Unit
	if len(cert.Subject.OrganizationalUnit) > 0 {
		for _, ou := range cert.Subject.OrganizationalUnit {
			if strings.HasPrefix(ou, "vlan=") {
				vlanStr := strings.TrimPrefix(ou, "vlan=")
				vlan, err := strconv.ParseUint(vlanStr, 10, 16)
				if err != nil {
					continue
				}
				if vlan < 1 || vlan > 4094 {
					return 0, ErrInvalidVLAN
				}
				return uint16(vlan), nil
			}
		}
	}

	return 0, ErrMissingVLAN
}

// ExtractACLs extracts ACL rules from certificate
func (e *X509PolicyExtractor) ExtractACLs(cert *x509.Certificate) ([]ACLRule, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	var acls []ACLRule

	// Try to extract from extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(e.OIDACLs) {
			// ACLs are encoded as a sequence of strings in ASN.1 format
			// Each string represents an ACL rule in a specific format
			var aclStrings []string
			if _, err := asn1.Unmarshal(ext.Value, &aclStrings); err == nil {
				for i, aclStr := range aclStrings {
					acl, err := parseACLRule(aclStr, i)
					if err != nil {
						continue // Skip invalid ACL rules
					}
					acls = append(acls, acl)
				}
				return acls, nil
			}
		}
	}

	// Return default ACLs if none found in certificate
	return e.getDefaultACLs(), nil
}

// getDefaultACLs returns default ACL rules for authenticated ports
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

// parseACLRule parses an ACL rule from string format
// Format: "priority=100,proto=tcp,dst_port=443,action=allow"
func parseACLRule(rule string, index int) (ACLRule, error) {
	acl := ACLRule{
		Priority: 100 - index, // Default priority decreases with index
		Match:    FlowMatch{},
		Action: FlowAction{
			Type: FlowActionAllow,
		},
	}

	parts := strings.Split(rule, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "priority":
			if p, err := strconv.Atoi(value); err == nil {
				acl.Priority = p
			}
		case "proto":
			switch value {
			case "tcp":
				acl.Match.IPProto = 6
			case "udp":
				acl.Match.IPProto = 17
			}
		case "src_ip":
			acl.Match.IPv4Src = value
		case "dst_ip":
			acl.Match.IPv4Dst = value
		case "src_port":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				switch acl.Match.IPProto {
				case 6:
					acl.Match.TCPSrc = uint16(p)
				case 17:
					acl.Match.UDPSrc = uint16(p)
				}
			}
		case "dst_port":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				switch acl.Match.IPProto {
				case 6:
					acl.Match.TCPDst = uint16(p)
				case 17:
					acl.Match.UDPDst = uint16(p)
				}
			}
		case "action":
			acl.Action.Type = FlowActionType(value)
		case "description":
			acl.Description = value
		}
	}

	return acl, nil
}

// DefaultCertificateValidator provides basic certificate validation
type DefaultCertificateValidator struct {
	// Roots is the trusted root CA pool
	Roots *x509.CertPool

	// Intermediates is the intermediate CA pool
	Intermediates *x509.CertPool

	// RevocationList contains revoked certificate serial numbers
	RevocationList map[string]bool
}

// NewDefaultCertificateValidator creates a new certificate validator
func NewDefaultCertificateValidator(roots, intermediates *x509.CertPool) *DefaultCertificateValidator {
	return &DefaultCertificateValidator{
		Roots:          roots,
		Intermediates:  intermediates,
		RevocationList: make(map[string]bool),
	}
}

// ValidateCertificate validates a certificate
func (v *DefaultCertificateValidator) ValidateCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	// Check expiry
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// Check revocation
	revoked, err := v.IsRevoked(cert)
	if err != nil {
		return fmt.Errorf("revocation check failed: %w", err)
	}
	if revoked {
		return ErrCertificateRevoked
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: v.Intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// IsRevoked checks if a certificate has been revoked
func (v *DefaultCertificateValidator) IsRevoked(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, ErrInvalidCertificate
	}

	serialNumber := cert.SerialNumber.String()
	return v.RevocationList[serialNumber], nil
}

// CheckExpiry checks if a certificate will expire within the threshold
func (v *DefaultCertificateValidator) CheckExpiry(cert *x509.Certificate, threshold time.Duration) error {
	if cert == nil {
		return ErrInvalidCertificate
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	if now.Add(threshold).After(cert.NotAfter) {
		return fmt.Errorf("certificate expires within %v: %w", threshold, ErrCertificateExpired)
	}

	return nil
}

// AddRevoked adds a certificate to the revocation list
func (v *DefaultCertificateValidator) AddRevoked(serialNumber string) {
	v.RevocationList[serialNumber] = true
}

// RemoveRevoked removes a certificate from the revocation list
func (v *DefaultCertificateValidator) RemoveRevoked(serialNumber string) {
	delete(v.RevocationList, serialNumber)
}

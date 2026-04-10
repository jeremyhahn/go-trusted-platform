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

package iam

import (
	"context"
	"crypto/x509"
	"encoding/asn1"

	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
)

// TCG OID constants for TPM device identity certificates.
// These OIDs are defined by the Trusted Computing Group (TCG) and are used
// to identify TPM-based device identity and attestation key certificates.
var (
	// OIDTCGIDevID is the OID for TPM 2.0 IDevID certificates (2.23.133.5.4.2).
	// IDevID (Initial Device Identifier) is a device identity credential
	// provisioned by the device manufacturer.
	OIDTCGIDevID = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2}

	// OIDTCGIak is the OID for TPM 2.0 IAK certificates (2.23.133.5.4.1).
	// IAK (Initial Attestation Key) is used for TPM remote attestation
	// and signing TPM quotes.
	OIDTCGIAK = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

	// OIDTCGManufacturer is the OID for TPM manufacturer information (2.23.133.2.1).
	OIDTCGManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}

	// OIDTCGModel is the OID for TPM model information (2.23.133.2.2).
	OIDTCGModel = asn1.ObjectIdentifier{2, 23, 133, 2, 2}

	// OIDTCGVersion is the OID for TPM version information (2.23.133.2.3).
	OIDTCGVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

// AttestationVerifier provides methods for verifying TPM attestation certificates.
// It validates IDevID and IAK certificates according to TCG specifications and
// can be used by the IAM middleware to verify device identity during authentication.
type AttestationVerifier interface {
	// VerifyIDevID validates an IDevID certificate according to TCG specifications.
	// It checks for proper key usage, required OIDs, and certificate structure.
	// Returns an error if the certificate is invalid or does not meet IDevID requirements.
	VerifyIDevID(ctx context.Context, cert *x509.Certificate) error

	// VerifyIAK validates an IAK certificate according to TCG specifications.
	// It checks for proper key usage, required OIDs, and certificate structure.
	// Returns an error if the certificate is invalid or does not meet IAK requirements.
	VerifyIAK(ctx context.Context, cert *x509.Certificate) error

	// IsIDevIDCertificate checks if a certificate contains IDevID OIDs.
	// Returns true if the certificate has the TCG IDevID OID (2.23.133.5.4.2)
	// or TPM manufacturer/model/version OIDs that indicate an IDevID certificate.
	IsIDevIDCertificate(cert *x509.Certificate) bool

	// IsIAKCertificate checks if a certificate contains IAK OIDs.
	// Returns true if the certificate has the TCG IAK OID (2.23.133.5.4.1)
	// or TPM manufacturer OID that indicates an IAK certificate.
	IsIAKCertificate(cert *x509.Certificate) bool
}

// AttestationConfig holds configuration for the attestation verifier.
type AttestationConfig struct {
	// RequireTPMAttestation requires valid TPM attestation for all certificates.
	RequireTPMAttestation bool

	// ValidateIDevID enables IDevID certificate validation.
	ValidateIDevID bool

	// ValidateIAK enables IAK certificate validation.
	ValidateIAK bool
}

// AttestationOption is a functional option for configuring AttestationConfig.
type AttestationOption func(*AttestationConfig)

// WithRequireTPMAttestation sets whether TPM attestation is required.
func WithRequireTPMAttestation(require bool) AttestationOption {
	return func(c *AttestationConfig) {
		c.RequireTPMAttestation = require
	}
}

// WithValidateIDevID enables or disables IDevID certificate validation.
func WithValidateIDevID(validate bool) AttestationOption {
	return func(c *AttestationConfig) {
		c.ValidateIDevID = validate
	}
}

// WithValidateIAK enables or disables IAK certificate validation.
func WithValidateIAK(validate bool) AttestationOption {
	return func(c *AttestationConfig) {
		c.ValidateIAK = validate
	}
}

// attestationVerifier implements the AttestationVerifier interface.
type attestationVerifier struct {
	config *AttestationConfig
}

// NewAttestationVerifier creates a new AttestationVerifier with the given options.
// If no options are provided, a default configuration is used with validation disabled.
func NewAttestationVerifier(opts ...AttestationOption) AttestationVerifier {
	config := &AttestationConfig{
		RequireTPMAttestation: false,
		ValidateIDevID:        false,
		ValidateIAK:           false,
	}

	for _, opt := range opts {
		opt(config)
	}

	return &attestationVerifier{
		config: config,
	}
}

// VerifyIDevID validates an IDevID certificate according to TCG specifications.
// It wraps errors from the auth package in IAM-specific error types.
func (av *attestationVerifier) VerifyIDevID(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return ErrCertificateInvalid{Reason: "nil certificate provided"}
	}

	// Skip validation if not configured
	if !av.config.ValidateIDevID && !av.config.RequireTPMAttestation {
		return nil
	}

	// Use the auth package validator
	if err := auth.ValidateIDevID(ctx, cert); err != nil {
		return wrapAttestationError(err, "IDevID")
	}

	return nil
}

// VerifyIAK validates an IAK certificate according to TCG specifications.
// It wraps errors from the auth package in IAM-specific error types.
func (av *attestationVerifier) VerifyIAK(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return ErrCertificateInvalid{Reason: "nil certificate provided"}
	}

	// Skip validation if not configured
	if !av.config.ValidateIAK && !av.config.RequireTPMAttestation {
		return nil
	}

	// Use the auth package validator
	if err := auth.ValidateIAK(ctx, cert); err != nil {
		return wrapAttestationError(err, "IAK")
	}

	return nil
}

// IsIDevIDCertificate checks if a certificate contains IDevID OIDs.
func (av *attestationVerifier) IsIDevIDCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGIDevID) {
			return true
		}
	}

	// Fallback: check for TPM manufacturer/model/version OIDs
	// These indicate a TPM-bound certificate which may be an IDevID
	return hasTPMIdentityOIDs(cert)
}

// IsIAKCertificate checks if a certificate contains IAK OIDs.
func (av *attestationVerifier) IsIAKCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGIAK) {
			return true
		}
	}

	// Fallback: check for TPM manufacturer OID
	// IAK certificates typically include manufacturer information
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGManufacturer) {
			return true
		}
	}

	return false
}

// hasTPMIdentityOIDs checks if a certificate contains any TCG TPM identity OIDs.
func hasTPMIdentityOIDs(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGManufacturer) ||
			ext.Id.Equal(OIDTCGModel) ||
			ext.Id.Equal(OIDTCGVersion) {
			return true
		}
	}
	return false
}

// wrapAttestationError wraps errors from the auth package in IAM-specific error types.
func wrapAttestationError(err error, certType string) error {
	switch e := err.(type) {
	case auth.ErrNilCertificate:
		return ErrCertificateInvalid{Reason: "nil certificate provided"}
	case auth.ErrInvalidKeyUsage:
		return ErrCertificateInvalid{
			Reason: certType + " certificate: invalid key usage: expected " + e.Expected + ", got " + e.Actual,
		}
	case auth.ErrTPMAttestationFailed:
		return ErrCertificateInvalid{
			Reason: certType + " attestation failed: " + e.Reason,
		}
	default:
		return ErrCertificateInvalid{
			Reason: certType + " validation failed: " + err.Error(),
		}
	}
}

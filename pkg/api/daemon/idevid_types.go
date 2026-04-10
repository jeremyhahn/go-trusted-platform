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
	"crypto/x509"
	"strings"
	"time"
)

// DeviceIdentityCertificate represents a device identity certificate for API responses.
// This is an API DTO with presentation fields not in x509.Certificate.
type DeviceIdentityCertificate struct {
	// Certificate is the parsed X.509 certificate.
	Certificate *x509.Certificate

	// PEM is the PEM-encoded certificate.
	PEM []byte

	// DER is the DER-encoded certificate.
	DER []byte

	// KeyType identifies the type of key (IDevID, IAK, LDevID, LAK).
	KeyType string

	// TPMHandle is the TPM persistent handle for the associated key.
	TPMHandle uint32

	// IssuedAt is when the certificate was issued.
	IssuedAt time.Time

	// ExpiresAt is when the certificate expires.
	ExpiresAt time.Time

	// IssuerCN is the issuer common name.
	IssuerCN string

	// SubjectCN is the subject common name.
	SubjectCN string

	// SerialNumber is the certificate serial number.
	SerialNumber string

	// Fingerprint is the SHA-256 fingerprint of the certificate.
	Fingerprint string
}

// KeyInfo contains information about a device identity key for API responses.
// This is an API DTO with presentation fields computed from KeyAttributes.
type KeyInfo struct {
	// Handle is the TPM persistent handle.
	Handle uint32

	// Algorithm is the key algorithm (e.g., "ECDSA-P256", "RSA-2048").
	Algorithm string

	// PublicKeyPEM is the PEM-encoded public key.
	PublicKeyPEM []byte

	// CreatedAt is when the key was created.
	CreatedAt time.Time

	// HasCertificate indicates if a certificate is installed.
	HasCertificate bool

	// CertificateInfo contains certificate details if installed.
	CertificateInfo *DeviceIdentityCertificate
}

// normalizeKeyAlgorithm normalizes algorithm string input to standard format.
// Accepts various formats and returns canonical form (e.g., "ECDSA-P256").
// Returns default "ECDSA-P256" for empty or unrecognized input.
func normalizeKeyAlgorithm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "ecdsa-p256", "p256", "ec-p256", "ecp256":
		return "ECDSA-P256"
	case "ecdsa-p384", "p384", "ec-p384", "ecp384":
		return "ECDSA-P384"
	case "rsa-2048", "rsa2048":
		return "RSA-2048"
	case "rsa-3072", "rsa3072":
		return "RSA-3072"
	default:
		return "ECDSA-P256" // Default
	}
}

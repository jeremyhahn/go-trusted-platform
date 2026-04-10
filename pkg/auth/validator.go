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

// TCG OIDs for device identity certificates
var (
	// OID for TPM 2.0 IDevID certificates (2.23.133.5.4.2)
	oidTCGIDevID = []int{2, 23, 133, 5, 4, 2}

	// OID for TPM 2.0 IAK certificates (2.23.133.5.4.1)
	oidTCGIAK = []int{2, 23, 133, 5, 4, 1}

	// OID for TPM manufacturer (2.23.133.2.1)
	oidTCGManufacturer = []int{2, 23, 133, 2, 1}

	// OID for TPM model (2.23.133.2.2)
	oidTCGModel = []int{2, 23, 133, 2, 2}

	// OID for TPM version (2.23.133.2.3)
	oidTCGVersion = []int{2, 23, 133, 2, 3}
)

// ValidateCertificate validates a certificate against trusted roots.
func ValidateCertificate(ctx context.Context, cert *x509.Certificate, roots *x509.CertPool) error {
	if cert == nil {
		return ErrNilCertificate{}
	}

	if roots == nil {
		return ErrMissingTrustedRoots{}
	}

	// Check time validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateInvalid{Reason: "certificate not yet valid"}
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired{}
	}

	// Verify against roots
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return ErrChainValidationFailed{Cause: err}
	}

	return nil
}

// ValidateIDevID validates an IDevID certificate per TCG specifications.
// TCG TPM 2.0 Keys for Device Identity and Attestation specifies:
//   - Key usage: Digital Signature only
//   - Extended key usage: id-kp-cmcRA (optional)
//   - Contains TPM-specific OIDs for manufacturer, model, version
func ValidateIDevID(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return ErrNilCertificate{}
	}

	// IDevID certificates should have Digital Signature key usage
	if !HasKeyUsage(cert, x509.KeyUsageDigitalSignature) {
		return ErrInvalidKeyUsage{
			Expected: "DigitalSignature",
			Actual:   "missing DigitalSignature",
		}
	}

	// Check for IDevID-specific OID in extensions
	hasIDevIDOID := false
	for _, ext := range cert.Extensions {
		if oidEqual(ext.Id, oidTCGIDevID) {
			hasIDevIDOID = true
			break
		}
	}

	// If no IDevID OID, check for TPM manufacturer info as fallback
	if !hasIDevIDOID {
		hasTPMInfo := false
		for _, ext := range cert.Extensions {
			if oidEqual(ext.Id, oidTCGManufacturer) ||
				oidEqual(ext.Id, oidTCGModel) ||
				oidEqual(ext.Id, oidTCGVersion) {
				hasTPMInfo = true
				break
			}
		}
		if !hasTPMInfo {
			return ErrTPMAttestationFailed{Reason: "certificate does not contain IDevID or TPM OIDs"}
		}
	}

	return nil
}

// ValidateIAK validates an IAK (Initial Attestation Key) certificate.
// TCG specifications require:
//   - Key usage: Digital Signature only
//   - Used for remote attestation (signing quotes)
func ValidateIAK(ctx context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return ErrNilCertificate{}
	}

	// IAK certificates should have Digital Signature key usage
	if !HasKeyUsage(cert, x509.KeyUsageDigitalSignature) {
		return ErrInvalidKeyUsage{
			Expected: "DigitalSignature",
			Actual:   "missing DigitalSignature",
		}
	}

	// Check for IAK-specific OID in extensions
	hasIAKOID := false
	for _, ext := range cert.Extensions {
		if oidEqual(ext.Id, oidTCGIAK) {
			hasIAKOID = true
			break
		}
	}

	if !hasIAKOID {
		// Fallback: check for TPM info OIDs
		hasTPMInfo := false
		for _, ext := range cert.Extensions {
			if oidEqual(ext.Id, oidTCGManufacturer) {
				hasTPMInfo = true
				break
			}
		}
		if !hasTPMInfo {
			return ErrTPMAttestationFailed{Reason: "certificate does not contain IAK or TPM OIDs"}
		}
	}

	return nil
}

// HasKeyUsage checks if a certificate has the specified key usage.
func HasKeyUsage(cert *x509.Certificate, usage x509.KeyUsage) bool {
	if cert == nil {
		return false
	}
	return cert.KeyUsage&usage != 0
}

// HasExtKeyUsage checks if a certificate has the specified extended key usage.
func HasExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == usage {
			return true
		}
	}
	return false
}

// HasAnyExtKeyUsage checks if a certificate has any of the specified extended key usages.
func HasAnyExtKeyUsage(cert *x509.Certificate, usages ...x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if HasExtKeyUsage(cert, usage) {
			return true
		}
	}
	return false
}

// RequireExtKeyUsage validates that a certificate has the specified extended key usage.
func RequireExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) error {
	if !HasExtKeyUsage(cert, usage) {
		return ErrInvalidExtKeyUsage{Expected: extKeyUsageToString(usage)}
	}
	return nil
}

// IsClientAuthCertificate checks if a certificate is valid for client authentication.
func IsClientAuthCertificate(cert *x509.Certificate) bool {
	return HasExtKeyUsage(cert, x509.ExtKeyUsageClientAuth) ||
		HasExtKeyUsage(cert, x509.ExtKeyUsageAny)
}

// IsServerAuthCertificate checks if a certificate is valid for server authentication.
func IsServerAuthCertificate(cert *x509.Certificate) bool {
	return HasExtKeyUsage(cert, x509.ExtKeyUsageServerAuth) ||
		HasExtKeyUsage(cert, x509.ExtKeyUsageAny)
}

// IsCACertificate checks if a certificate is a CA certificate.
func IsCACertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return cert.IsCA
}

// IsExpired checks if a certificate has expired.
func IsExpired(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().After(cert.NotAfter)
}

// IsNotYetValid checks if a certificate is not yet valid.
func IsNotYetValid(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	return time.Now().Before(cert.NotBefore)
}

// ValidityRemaining returns the duration until the certificate expires.
func ValidityRemaining(cert *x509.Certificate) time.Duration {
	if cert == nil {
		return 0
	}
	return time.Until(cert.NotAfter)
}

// oidEqual compares two OIDs for equality.
func oidEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// extKeyUsageToString converts an ExtKeyUsage to a human-readable string.
func extKeyUsageToString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeServerGatedCrypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "MicrosoftCommercialCodeSigning"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "MicrosoftKernelCodeSigning"
	default:
		return "Unknown"
	}
}

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

package ca

import "fmt"

// ErrCANotInitialized is returned when the CA service is not initialized
type ErrCANotInitialized struct{}

func (e ErrCANotInitialized) Error() string {
	return "certificate authority not initialized"
}

// ErrCertificateNotFound is returned when a certificate cannot be found
type ErrCertificateNotFound struct {
	Serial string
}

func (e ErrCertificateNotFound) Error() string {
	if e.Serial != "" {
		return fmt.Sprintf("certificate not found: %s", e.Serial)
	}
	return "certificate not found"
}

// ErrInvalidSerialNumber is returned when an invalid serial number is provided
type ErrInvalidSerialNumber struct {
	Serial string
	Reason string
}

func (e ErrInvalidSerialNumber) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid serial number '%s': %s", e.Serial, e.Reason)
	}
	return fmt.Sprintf("invalid serial number: %s", e.Serial)
}

// ErrCertificateRevoked is returned when a certificate has been revoked
type ErrCertificateRevoked struct {
	Serial string
}

func (e ErrCertificateRevoked) Error() string {
	if e.Serial != "" {
		return fmt.Sprintf("certificate has been revoked: %s", e.Serial)
	}
	return "certificate has been revoked"
}

// ErrCRLGenerationFailed is returned when CRL generation fails
type ErrCRLGenerationFailed struct {
	Reason string
}

func (e ErrCRLGenerationFailed) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("CRL generation failed: %s", e.Reason)
	}
	return "CRL generation failed"
}

// ErrInvalidCertificateRequest is returned when a certificate request is invalid
type ErrInvalidCertificateRequest struct {
	Reason string
}

func (e ErrInvalidCertificateRequest) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid certificate request: %s", e.Reason)
	}
	return "invalid certificate request"
}

// ErrInvalidRequestBody is returned when the request body cannot be parsed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrMissingSubject is returned when a certificate subject is required but not provided
type ErrMissingSubject struct{}

func (e ErrMissingSubject) Error() string {
	return "certificate subject is required"
}

// ErrMissingCommonName is returned when common name is required but not provided
type ErrMissingCommonName struct{}

func (e ErrMissingCommonName) Error() string {
	return "common name is required"
}

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
	Reason    string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid key algorithm '%s': %s", e.Algorithm, e.Reason)
	}
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrInvalidValidityPeriod is returned when an invalid validity period is specified
type ErrInvalidValidityPeriod struct {
	Days   int
	Reason string
}

func (e ErrInvalidValidityPeriod) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid validity period %d days: %s", e.Days, e.Reason)
	}
	return fmt.Sprintf("invalid validity period: %d days", e.Days)
}

// ErrInvalidRevocationReason is returned when an invalid revocation reason is specified
type ErrInvalidRevocationReason struct {
	Reason int
}

func (e ErrInvalidRevocationReason) Error() string {
	return fmt.Sprintf("invalid revocation reason code: %d", e.Reason)
}

// ErrBundleNotFound is returned when the CA bundle cannot be found
type ErrBundleNotFound struct{}

func (e ErrBundleNotFound) Error() string {
	return "CA bundle not found"
}

// ErrCRLNotFound is returned when the CRL cannot be found
type ErrCRLNotFound struct{}

func (e ErrCRLNotFound) Error() string {
	return "certificate revocation list not found"
}

// ErrInvalidStoreType is returned when an invalid key store type is specified
type ErrInvalidStoreType struct {
	StoreType string
}

func (e ErrInvalidStoreType) Error() string {
	return fmt.Sprintf("invalid store type: %s", e.StoreType)
}

// ErrInvalidPaginationParams is returned when pagination parameters are invalid
type ErrInvalidPaginationParams struct {
	Reason string
}

func (e ErrInvalidPaginationParams) Error() string {
	return fmt.Sprintf("invalid pagination parameters: %s", e.Reason)
}

// ErrBootstrapBundleFailed is returned when the bootstrap bundle retrieval fails.
type ErrBootstrapBundleFailed struct {
	Cause error
}

func (e ErrBootstrapBundleFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap bundle retrieval failed: %v", e.Cause)
	}
	return "bootstrap bundle retrieval failed"
}

func (e ErrBootstrapBundleFailed) Unwrap() error {
	return e.Cause
}

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

import "fmt"

// ErrAuthenticationFailed indicates a general authentication failure.
type ErrAuthenticationFailed struct {
	Reason string
}

func (e ErrAuthenticationFailed) Error() string {
	if e.Reason == "" {
		return "auth: authentication failed"
	}
	return fmt.Sprintf("auth: authentication failed: %s", e.Reason)
}

// ErrCertificateInvalid indicates a certificate validation failure.
type ErrCertificateInvalid struct {
	Reason string
}

func (e ErrCertificateInvalid) Error() string {
	if e.Reason == "" {
		return "auth: certificate invalid"
	}
	return fmt.Sprintf("auth: certificate invalid: %s", e.Reason)
}

// ErrCertificateExpired indicates the certificate has expired.
type ErrCertificateExpired struct{}

func (e ErrCertificateExpired) Error() string {
	return "auth: certificate expired"
}

// ErrCertificateRevoked indicates the certificate has been revoked.
type ErrCertificateRevoked struct{}

func (e ErrCertificateRevoked) Error() string {
	return "auth: certificate revoked"
}

// ErrChainValidationFailed indicates certificate chain validation failed.
type ErrChainValidationFailed struct {
	Cause error
}

func (e ErrChainValidationFailed) Error() string {
	if e.Cause == nil {
		return "auth: certificate chain validation failed"
	}
	return fmt.Sprintf("auth: certificate chain validation failed: %v", e.Cause)
}

// Unwrap returns the underlying cause of the chain validation failure.
func (e ErrChainValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrIdentityNotFound indicates no identity could be extracted from the certificate.
type ErrIdentityNotFound struct{}

func (e ErrIdentityNotFound) Error() string {
	return "auth: identity not found in certificate"
}

// ErrTenantNotFound indicates no tenant could be extracted from the certificate.
type ErrTenantNotFound struct{}

func (e ErrTenantNotFound) Error() string {
	return "auth: tenant not found in certificate"
}

// ErrTPMAttestationFailed indicates TPM attestation verification failed.
type ErrTPMAttestationFailed struct {
	Reason string
}

func (e ErrTPMAttestationFailed) Error() string {
	if e.Reason == "" {
		return "auth: TPM attestation failed"
	}
	return fmt.Sprintf("auth: TPM attestation failed: %s", e.Reason)
}

// ErrNilCertificate indicates a nil certificate was provided.
type ErrNilCertificate struct{}

func (e ErrNilCertificate) Error() string {
	return "auth: nil certificate provided"
}

// ErrNilLogger indicates a nil logger was provided.
type ErrNilLogger struct{}

func (e ErrNilLogger) Error() string {
	return "auth: nil logger provided"
}

// ErrNilCA indicates a nil certificate authority was provided.
type ErrNilCA struct{}

func (e ErrNilCA) Error() string {
	return "auth: nil certificate authority provided"
}

// ErrMissingTrustedRoots indicates no trusted roots were configured.
type ErrMissingTrustedRoots struct{}

func (e ErrMissingTrustedRoots) Error() string {
	return "auth: no trusted roots configured"
}

// ErrRevocationCheckFailed indicates a certificate revocation check failed.
type ErrRevocationCheckFailed struct {
	Reason string
}

func (e ErrRevocationCheckFailed) Error() string {
	if e.Reason == "" {
		return "auth: revocation check failed"
	}
	return fmt.Sprintf("auth: revocation check failed: %s", e.Reason)
}

// ErrInvalidKeyUsage indicates the certificate does not have required key usage.
type ErrInvalidKeyUsage struct {
	Expected string
	Actual   string
}

func (e ErrInvalidKeyUsage) Error() string {
	return fmt.Sprintf("auth: invalid key usage: expected %s, got %s", e.Expected, e.Actual)
}

// ErrInvalidExtKeyUsage indicates the certificate does not have required extended key usage.
type ErrInvalidExtKeyUsage struct {
	Expected string
}

func (e ErrInvalidExtKeyUsage) Error() string {
	return fmt.Sprintf("auth: missing extended key usage: %s", e.Expected)
}

// ErrRevocationRequiresCA indicates revocation checking was requested on an
// adapter constructed without a certificate authority. Revocation state
// lives in the CA; silently skipping the check would be fail-open, so the
// combination is rejected at construction time.
type ErrRevocationRequiresCA struct{}

func (e ErrRevocationRequiresCA) Error() string {
	return "auth: revocation checking requires a certificate authority"
}

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

package eab

import "fmt"

// ErrInvalidRequestBody indicates the request body is invalid or malformed.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	if e.Reason != "" {
		return "eab: invalid request body: " + e.Reason
	}
	return "eab: invalid request body"
}

// ErrMissingProfileID indicates the profile ID field is required but not provided.
type ErrMissingProfileID struct{}

func (e ErrMissingProfileID) Error() string {
	return "eab: profile_id is required"
}

// ErrInvalidProfileID indicates the profile ID format is invalid.
type ErrInvalidProfileID struct {
	ID string
}

func (e ErrInvalidProfileID) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("eab: invalid profile_id: %s", e.ID)
	}
	return "eab: invalid profile_id"
}

// ErrMissingTenantID indicates the tenant ID field is required but not provided.
type ErrMissingTenantID struct{}

func (e ErrMissingTenantID) Error() string {
	return "eab: tenant_id is required"
}

// ErrMissingCredentialID indicates the credential ID is required but not provided.
type ErrMissingCredentialID struct{}

func (e ErrMissingCredentialID) Error() string {
	return "eab: credential id is required"
}

// ErrInvalidCredentialID indicates the credential ID format is invalid.
type ErrInvalidCredentialID struct {
	ID string
}

func (e ErrInvalidCredentialID) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("eab: invalid credential id: %s", e.ID)
	}
	return "eab: invalid credential id"
}

// ErrMissingKeyID indicates the key ID is required but not provided.
type ErrMissingKeyID struct{}

func (e ErrMissingKeyID) Error() string {
	return "eab: key_id is required"
}

// ErrMissingHMACKey indicates the HMAC key is required but not provided.
type ErrMissingHMACKey struct{}

func (e ErrMissingHMACKey) Error() string {
	return "eab: hmac_key is required"
}

// ErrInvalidHMACKey indicates the HMAC key format is invalid.
type ErrInvalidHMACKey struct {
	Reason string
}

func (e ErrInvalidHMACKey) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("eab: invalid hmac_key: %s", e.Reason)
	}
	return "eab: invalid hmac_key"
}

// ErrCredentialNotFound indicates the credential was not found.
type ErrCredentialNotFound struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialNotFound) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential not found: key_id=%s", e.KeyID)
	}
	if e.ID > 0 {
		return fmt.Sprintf("eab: credential not found: id=%d", e.ID)
	}
	return "eab: credential not found"
}

// ErrCredentialExpired indicates the credential has expired.
type ErrCredentialExpired struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialExpired) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential expired: key_id=%s", e.KeyID)
	}
	if e.ID > 0 {
		return fmt.Sprintf("eab: credential expired: id=%d", e.ID)
	}
	return "eab: credential expired"
}

// ErrCredentialRevoked indicates the credential has been revoked.
type ErrCredentialRevoked struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialRevoked) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential revoked: key_id=%s", e.KeyID)
	}
	if e.ID > 0 {
		return fmt.Sprintf("eab: credential revoked: id=%d", e.ID)
	}
	return "eab: credential revoked"
}

// ErrCredentialAlreadyUsed indicates the credential has already been used.
type ErrCredentialAlreadyUsed struct {
	ID    uint64
	KeyID string
}

func (e ErrCredentialAlreadyUsed) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("eab: credential already used: key_id=%s", e.KeyID)
	}
	if e.ID > 0 {
		return fmt.Sprintf("eab: credential already used: id=%d", e.ID)
	}
	return "eab: credential already used"
}

// ErrCredentialAlreadyRevoked indicates the credential was already revoked.
type ErrCredentialAlreadyRevoked struct {
	ID uint64
}

func (e ErrCredentialAlreadyRevoked) Error() string {
	if e.ID > 0 {
		return fmt.Sprintf("eab: credential already revoked: id=%d", e.ID)
	}
	return "eab: credential already revoked"
}

// ErrUnauthorized indicates the user is not authenticated.
type ErrUnauthorized struct {
	Reason string
}

func (e ErrUnauthorized) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("eab: unauthorized: %s", e.Reason)
	}
	return "eab: unauthorized"
}

// ErrNotTenantOwner indicates the user is not the tenant owner.
type ErrNotTenantOwner struct{}

func (e ErrNotTenantOwner) Error() string {
	return "eab: only tenant owner can perform this operation"
}

// ErrServiceError indicates an internal service error occurred.
type ErrServiceError struct {
	Operation string
	Cause     error
}

func (e ErrServiceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("eab: %s failed: %s", e.Operation, e.Cause.Error())
	}
	return fmt.Sprintf("eab: %s failed", e.Operation)
}

func (e ErrServiceError) Unwrap() error {
	return e.Cause
}

// ErrMissingLogger indicates the logger is required but not provided.
type ErrMissingLogger struct{}

func (e ErrMissingLogger) Error() string {
	return "eab: logger is required"
}

// ErrMissingEABService indicates the EAB service is required but not provided.
type ErrMissingEABService struct{}

func (e ErrMissingEABService) Error() string {
	return "eab: eab service is required"
}

// ErrMissingResponseWriter indicates the response writer is required but not provided.
type ErrMissingResponseWriter struct{}

func (e ErrMissingResponseWriter) Error() string {
	return "eab: response writer is required"
}

// ErrMissingDelivery indicates the delivery service is required but not provided.
type ErrMissingDelivery struct{}

func (e ErrMissingDelivery) Error() string {
	return "eab: delivery service is required"
}

// ErrQRCodeGenerationFailed indicates QR code generation failed.
type ErrQRCodeGenerationFailed struct {
	Cause error
}

func (e ErrQRCodeGenerationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("eab: QR code generation failed: %s", e.Cause.Error())
	}
	return "eab: QR code generation failed"
}

func (e ErrQRCodeGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrURLGenerationFailed indicates URL generation failed.
type ErrURLGenerationFailed struct {
	Cause error
}

func (e ErrURLGenerationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("eab: URL generation failed: %s", e.Cause.Error())
	}
	return "eab: URL generation failed"
}

func (e ErrURLGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidExpiresIn indicates the expires_in value is invalid.
type ErrInvalidExpiresIn struct {
	Reason string
}

func (e ErrInvalidExpiresIn) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("eab: invalid expires_in: %s", e.Reason)
	}
	return "eab: invalid expires_in"
}

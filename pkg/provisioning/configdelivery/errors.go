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

package configdelivery

import "fmt"

// ErrInvalidRequest indicates the config request is malformed.
type ErrInvalidRequest struct {
	Reason string
}

// Error returns the error message.
func (e ErrInvalidRequest) Error() string {
	return fmt.Sprintf("configdelivery: invalid request: %s", e.Reason)
}

// ErrEABValidationFailed indicates EAB credential validation failed.
type ErrEABValidationFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrEABValidationFailed) Error() string {
	return fmt.Sprintf("configdelivery: eab validation failed: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrEABValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrNonceExpired indicates the nonce has expired or was already used.
type ErrNonceExpired struct{}

// Error returns the error message.
func (e ErrNonceExpired) Error() string {
	return "configdelivery: nonce expired or already used"
}

// ErrNonceRequired indicates a nonce is required but was not provided.
type ErrNonceRequired struct{}

// Error returns the error message.
func (e ErrNonceRequired) Error() string {
	return "configdelivery: nonce is required"
}

// ErrNonceGenerationFailed indicates nonce generation failed.
type ErrNonceGenerationFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrNonceGenerationFailed) Error() string {
	return fmt.Sprintf("configdelivery: nonce generation failed: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrNonceGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrSessionNotFound indicates the provisioning session was not found.
type ErrSessionNotFound struct {
	SessionID string
}

// Error returns the error message.
func (e ErrSessionNotFound) Error() string {
	return fmt.Sprintf("configdelivery: session not found: %s", e.SessionID)
}

// ErrSessionExpired indicates the provisioning session has expired.
type ErrSessionExpired struct {
	SessionID string
}

// Error returns the error message.
func (e ErrSessionExpired) Error() string {
	return fmt.Sprintf("configdelivery: session expired: %s", e.SessionID)
}

// ErrSessionAlreadyFulfilled indicates the session was already fulfilled.
type ErrSessionAlreadyFulfilled struct {
	SessionID string
}

// Error returns the error message.
func (e ErrSessionAlreadyFulfilled) Error() string {
	return fmt.Sprintf("configdelivery: session already fulfilled: %s", e.SessionID)
}

// ErrHMACMismatch indicates the HMAC signature does not match.
type ErrHMACMismatch struct{}

// Error returns the error message.
func (e ErrHMACMismatch) Error() string {
	return "configdelivery: hmac signature mismatch"
}

// ErrProfileNotFound indicates the requested profile was not found.
type ErrProfileNotFound struct {
	ProfileID uint64
}

// Error returns the error message.
func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("configdelivery: profile not found: %d", e.ProfileID)
}

// ErrMissingLogger indicates a logger is required but was not provided.
type ErrMissingLogger struct{}

// Error returns the error message.
func (e ErrMissingLogger) Error() string {
	return "configdelivery: logger is required"
}

// ErrMissingProfileService indicates a profile service is required but was not provided.
type ErrMissingProfileService struct{}

// Error returns the error message.
func (e ErrMissingProfileService) Error() string {
	return "configdelivery: profile service is required"
}

// ErrMissingEABService indicates an EAB service is required but was not provided.
type ErrMissingEABService struct{}

// Error returns the error message.
func (e ErrMissingEABService) Error() string {
	return "configdelivery: eab service is required"
}

// ErrMissingResponseWriter indicates a response writer is required but was not provided.
type ErrMissingResponseWriter struct{}

// Error returns the error message.
func (e ErrMissingResponseWriter) Error() string {
	return "configdelivery: response writer is required"
}

// ErrMissingService indicates a config delivery service is required but was not provided.
type ErrMissingService struct{}

// Error returns the error message.
func (e ErrMissingService) Error() string {
	return "configdelivery: service is required"
}

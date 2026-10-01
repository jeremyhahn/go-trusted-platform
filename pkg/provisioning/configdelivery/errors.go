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

// ErrSessionProfileMissing indicates a session is marked fulfilled but
// carries no resolved device profile, so no configuration can be delivered.
// This is an invalid-state condition: it occurs when a session was fulfilled
// with a bare profile ID while no profile service was configured to resolve
// the full profile.
type ErrSessionProfileMissing struct {
	SessionID string
}

// Error returns the error message.
func (e ErrSessionProfileMissing) Error() string {
	return fmt.Sprintf("configdelivery: session fulfilled without a resolved profile: %s", e.SessionID)
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

// ErrEKCertRequired indicates the matched profile is bound to a hardware EK
// (or EK matching is required) but the request did not present an EK
// certificate, or no EK certificate was prestaged to verify against.
type ErrEKCertRequired struct{}

// Error returns the error message.
func (e ErrEKCertRequired) Error() string {
	return "configdelivery: ek certificate required for hardware-bound profile"
}

// ErrEKCertMismatch indicates the public key of the presented EK certificate
// does not match the public key of the prestaged EK certificate.
type ErrEKCertMismatch struct{}

// Error returns the error message.
func (e ErrEKCertMismatch) Error() string {
	return "configdelivery: ek certificate public key mismatch"
}

// ErrEABProfileMismatch indicates a valid EAB credential presented for a device
// whose resolved profile is not the one (or not in the tenant) the credential
// was issued for. An EAB authorises exactly one expected device, so it can
// neither deliver another profile's config nor sign on another profile's behalf.
type ErrEABProfileMismatch struct{}

// Error returns the error message.
func (e ErrEABProfileMismatch) Error() string {
	return "configdelivery: eab credential is not bound to this device's profile"
}

// ErrEKCertParseFailed indicates an EK certificate could not be decoded or
// parsed into an x509 certificate.
type ErrEKCertParseFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrEKCertParseFailed) Error() string {
	return fmt.Sprintf("configdelivery: ek certificate parse failed: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrEKCertParseFailed) Unwrap() error {
	return e.Cause
}

// ErrEKCertNotPEM indicates the prestaged EK certificate is not valid PEM.
type ErrEKCertNotPEM struct{}

// Error returns the error message.
func (e ErrEKCertNotPEM) Error() string {
	return "configdelivery: prestaged ek certificate is not valid PEM"
}

// ErrUnsupportedEKKeyType indicates the EK certificate public key type does not
// support constant-time public-key equality comparison.
type ErrUnsupportedEKKeyType struct{}

// Error returns the error message.
func (e ErrUnsupportedEKKeyType) Error() string {
	return "configdelivery: unsupported ek certificate public key type"
}

// ErrRemoteSignNotConfigured indicates the resolved device profile is not
// provisioned for remote Secure Boot DB signing: secure boot is disabled, the
// resign-mode is not "remote", no DB key URI is present, or an unsupported key
// was requested.
type ErrRemoteSignNotConfigured struct {
	Reason string
}

// Error returns the error message.
func (e ErrRemoteSignNotConfigured) Error() string {
	if e.Reason == "" {
		return "configdelivery: remote signing not configured for this device"
	}
	return "configdelivery: remote signing not configured for this device: " + e.Reason
}

// ErrSignerUnavailable indicates no DB key signer is wired into the control
// plane, so the remote digest-signing endpoint cannot fulfil any request.
type ErrSignerUnavailable struct{}

// Error returns the error message.
func (e ErrSignerUnavailable) Error() string {
	return "configdelivery: remote signing is unavailable: no db key signer configured"
}

// ErrSignFailed indicates the control-plane KMS failed to sign the digest.
type ErrSignFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrSignFailed) Error() string {
	return fmt.Sprintf("configdelivery: digest signing failed: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrSignFailed) Unwrap() error {
	return e.Cause
}

// ErrCertUnavailable indicates the companion DB certificate could not be
// retrieved after a successful signature.
type ErrCertUnavailable struct {
	Cause error
}

// Error returns the error message.
func (e ErrCertUnavailable) Error() string {
	return fmt.Sprintf("configdelivery: db certificate unavailable: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrCertUnavailable) Unwrap() error {
	return e.Cause
}

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

package ceremony

// ErrInitFailed indicates a ceremony initialization failure.
type ErrInitFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrInitFailed) Error() string {
	return "ceremony: init failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrInitFailed) Unwrap() error { return e.Cause }

// ErrStatusFailed indicates a ceremony status fetch failure.
type ErrStatusFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrStatusFailed) Error() string {
	return "ceremony: status failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrStatusFailed) Unwrap() error { return e.Cause }

// ErrClaimCertBeginFailed indicates a claim-cert begin failure.
type ErrClaimCertBeginFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrClaimCertBeginFailed) Error() string {
	return "ceremony: claim-cert begin failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrClaimCertBeginFailed) Unwrap() error { return e.Cause }

// ErrClaimCertCompleteFailed indicates a claim-cert complete failure.
type ErrClaimCertCompleteFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrClaimCertCompleteFailed) Error() string {
	return "ceremony: claim-cert complete failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrClaimCertCompleteFailed) Unwrap() error { return e.Cause }

// ErrClaimShareFailed indicates a claim-share failure.
type ErrClaimShareFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrClaimShareFailed) Error() string {
	return "ceremony: claim-share failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrClaimShareFailed) Unwrap() error { return e.Cause }

// ErrSignCSRFailed indicates a sign-csr failure.
type ErrSignCSRFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrSignCSRFailed) Error() string {
	return "ceremony: sign-csr failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrSignCSRFailed) Unwrap() error { return e.Cause }

// ErrUnknownWireValue indicates a transport carried an enum value the SDK
// does not recognise. It is refused rather than reported as UNSPECIFIED.
type ErrUnknownWireValue struct {
	Kind  string
	Value string
}

// Error implements the error interface.
func (e *ErrUnknownWireValue) Error() string {
	return "ceremony: unknown " + e.Kind + " " + e.Value
}

// ErrWireDecode indicates a REST or MCP result could not be decoded.
type ErrWireDecode struct {
	Message string
	Err     error
}

// Error implements the error interface.
func (e *ErrWireDecode) Error() string {
	return "ceremony: decode " + e.Message + " result: " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrWireDecode) Unwrap() error { return e.Err }

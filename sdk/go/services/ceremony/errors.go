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

import "errors"

// ErrNotYetWired indicates the ceremony service handler has not yet been
// wired up on the server side. This is a deliberate placeholder returned by
// the Phase 3 SDK stubs; real implementations land in Phase 3.5.
var ErrNotYetWired = errors.New("ceremony: service not yet wired in this release")

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

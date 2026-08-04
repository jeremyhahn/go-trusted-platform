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

package provision

import "fmt"

// Validation Errors

// ErrNilRequest indicates a nil request message was passed to an operation.
type ErrNilRequest struct {
	Op string
}

func (e *ErrNilRequest) Error() string {
	return fmt.Sprintf("provision: nil request for %s", e.Op)
}

// ErrSessionIDRequired indicates the session ID argument is missing or empty.
type ErrSessionIDRequired struct{}

func (e *ErrSessionIDRequired) Error() string {
	return "provision: session ID is required"
}

// ErrProfileIDRequired indicates the profile ID argument is missing or zero.
type ErrProfileIDRequired struct{}

func (e *ErrProfileIDRequired) Error() string {
	return "provision: profile ID is required and must be non-zero"
}

// Operation Errors

// ErrGetNonceFailed indicates nonce issuance failed.
type ErrGetNonceFailed struct {
	Cause error
}

func (e *ErrGetNonceFailed) Error() string {
	return fmt.Sprintf("failed to get provisioning nonce: %v", e.Cause)
}

func (e *ErrGetNonceFailed) Unwrap() error { return e.Cause }

// ErrFetchConfigFailed indicates the pre-enrollment config fetch failed.
type ErrFetchConfigFailed struct {
	Cause error
}

func (e *ErrFetchConfigFailed) Error() string {
	return fmt.Sprintf("failed to fetch provisioning config: %v", e.Cause)
}

func (e *ErrFetchConfigFailed) Unwrap() error { return e.Cause }

// ErrSignDigestFailed indicates the remote Secure Boot digest signing failed.
type ErrSignDigestFailed struct {
	Cause error
}

func (e *ErrSignDigestFailed) Error() string {
	return fmt.Sprintf("failed to sign provisioning digest: %v", e.Cause)
}

func (e *ErrSignDigestFailed) Unwrap() error { return e.Cause }

// ErrPollSessionFailed indicates polling a provisioning session failed.
type ErrPollSessionFailed struct {
	SessionID string
	Cause     error
}

func (e *ErrPollSessionFailed) Error() string {
	return fmt.Sprintf("failed to poll provisioning session %s: %v", e.SessionID, e.Cause)
}

func (e *ErrPollSessionFailed) Unwrap() error { return e.Cause }

// ErrFulfillSessionFailed indicates fulfilling a provisioning session failed.
type ErrFulfillSessionFailed struct {
	SessionID string
	Cause     error
}

func (e *ErrFulfillSessionFailed) Error() string {
	return fmt.Sprintf("failed to fulfill provisioning session %s: %v", e.SessionID, e.Cause)
}

func (e *ErrFulfillSessionFailed) Unwrap() error { return e.Cause }

// ErrListSessionsFailed indicates listing provisioning sessions failed.
type ErrListSessionsFailed struct {
	Cause error
}

func (e *ErrListSessionsFailed) Error() string {
	return fmt.Sprintf("failed to list provisioning sessions: %v", e.Cause)
}

func (e *ErrListSessionsFailed) Unwrap() error { return e.Cause }

// ErrGetSessionFailed indicates fetching a provisioning session failed.
type ErrGetSessionFailed struct {
	SessionID string
	Cause     error
}

func (e *ErrGetSessionFailed) Error() string {
	return fmt.Sprintf("failed to get provisioning session %s: %v", e.SessionID, e.Cause)
}

func (e *ErrGetSessionFailed) Unwrap() error { return e.Cause }

// Wire Decode Errors

// ErrWireDecodeFailed indicates a REST/MCP JSON wire payload could not be
// decoded into the corresponding platform.v1 response message.
type ErrWireDecodeFailed struct {
	Op    string
	Cause error
}

func (e *ErrWireDecodeFailed) Error() string {
	return fmt.Sprintf("provision: failed to decode %s wire payload: %v", e.Op, e.Cause)
}

func (e *ErrWireDecodeFailed) Unwrap() error { return e.Cause }

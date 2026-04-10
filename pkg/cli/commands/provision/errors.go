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

// ErrServerURLRequired is returned when the server URL flag is not provided.
type ErrServerURLRequired struct{}

func (e ErrServerURLRequired) Error() string {
	return "provision: --server-url is required"
}

// ErrEKSerialRequired is returned when the EK serial flag is not provided.
type ErrEKSerialRequired struct{}

func (e ErrEKSerialRequired) Error() string {
	return "provision: --ek-serial is required"
}

// ErrMACRequired is returned when the MAC address flag is not provided.
type ErrMACRequired struct{}

func (e ErrMACRequired) Error() string {
	return "provision: --mac is required"
}

// ErrEABKIDRequired is returned when the EAB key ID flag is not provided.
type ErrEABKIDRequired struct{}

func (e ErrEABKIDRequired) Error() string {
	return "provision: --eab-kid is required"
}

// ErrEABHMACRequired is returned when the EAB HMAC flag is not provided.
type ErrEABHMACRequired struct{}

func (e ErrEABHMACRequired) Error() string {
	return "provision: --eab-hmac is required"
}

// ErrOutputRequired is returned when the output path flag is not provided.
type ErrOutputRequired struct{}

func (e ErrOutputRequired) Error() string {
	return "provision: --output is required"
}

// ErrNonceFetchFailed is returned when fetching the nonce from the server fails.
type ErrNonceFetchFailed struct {
	URL   string
	Cause error
}

func (e ErrNonceFetchFailed) Error() string {
	return fmt.Sprintf("provision: failed to fetch nonce from %s: %v", e.URL, e.Cause)
}

func (e ErrNonceFetchFailed) Unwrap() error {
	return e.Cause
}

// ErrConfigRequestFailed is returned when the config request to the server fails.
type ErrConfigRequestFailed struct {
	URL   string
	Cause error
}

func (e ErrConfigRequestFailed) Error() string {
	return fmt.Sprintf("provision: config request to %s failed: %v", e.URL, e.Cause)
}

func (e ErrConfigRequestFailed) Unwrap() error {
	return e.Cause
}

// ErrUnexpectedStatus is returned when the server returns an unexpected HTTP status.
type ErrUnexpectedStatus struct {
	StatusCode int
	Body       string
}

func (e ErrUnexpectedStatus) Error() string {
	return fmt.Sprintf("provision: unexpected HTTP status %d: %s", e.StatusCode, e.Body)
}

// ErrConfigWriteFailed is returned when writing the config to the output file fails.
type ErrConfigWriteFailed struct {
	Path  string
	Cause error
}

func (e ErrConfigWriteFailed) Error() string {
	return fmt.Sprintf("provision: failed to write config to %s: %v", e.Path, e.Cause)
}

func (e ErrConfigWriteFailed) Unwrap() error {
	return e.Cause
}

// ErrPollFailed is returned when a poll request to the server fails.
type ErrPollFailed struct {
	SessionID string
	Cause     error
}

func (e ErrPollFailed) Error() string {
	return fmt.Sprintf("provision: poll for session %s failed: %v", e.SessionID, e.Cause)
}

func (e ErrPollFailed) Unwrap() error {
	return e.Cause
}

// ErrPollTimeout is returned when polling exceeds the configured timeout.
type ErrPollTimeout struct {
	SessionID string
	Timeout   int
}

func (e ErrPollTimeout) Error() string {
	return fmt.Sprintf("provision: polling timed out after %ds for session %s", e.Timeout, e.SessionID)
}

// ErrResponseDecodeFailed is returned when decoding a server response fails.
type ErrResponseDecodeFailed struct {
	Cause error
}

func (e ErrResponseDecodeFailed) Error() string {
	return fmt.Sprintf("provision: failed to decode server response: %v", e.Cause)
}

func (e ErrResponseDecodeFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidTimeout is returned when the timeout value is invalid.
type ErrInvalidTimeout struct {
	Value int
}

func (e ErrInvalidTimeout) Error() string {
	return fmt.Sprintf("provision: invalid timeout value: %d (must be > 0)", e.Value)
}

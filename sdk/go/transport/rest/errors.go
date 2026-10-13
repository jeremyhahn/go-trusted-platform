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

// Package rest provides the REST transport adapter for the platform SDK.
package rest

import "fmt"

// ErrHTTPStatus represents an HTTP error response.
type ErrHTTPStatus struct {
	StatusCode int
	Status     string
	Body       string
}

// Error implements the error interface.
func (e ErrHTTPStatus) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d %s: %s", e.StatusCode, e.Status, e.Body)
	}
	return fmt.Sprintf("HTTP %d %s", e.StatusCode, e.Status)
}

// ErrRequestFailed represents a request failure.
type ErrRequestFailed struct {
	Method string
	Path   string
	Err    error
}

// Error implements the error interface.
func (e ErrRequestFailed) Error() string {
	return fmt.Sprintf("request %s %s failed: %v", e.Method, e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrRequestFailed) Unwrap() error {
	return e.Err
}

// ErrMarshalFailed represents a JSON marshaling failure.
type ErrMarshalFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrMarshalFailed) Error() string {
	return fmt.Sprintf("failed to marshal request: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrMarshalFailed) Unwrap() error {
	return e.Err
}

// ErrUnmarshalFailed represents a JSON unmarshaling failure.
type ErrUnmarshalFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrUnmarshalFailed) Error() string {
	return fmt.Sprintf("failed to unmarshal response: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrUnmarshalFailed) Unwrap() error {
	return e.Err
}

// ErrClientClosed indicates the client has been closed.
type ErrClientClosed struct{}

// Error implements the error interface.
func (e ErrClientClosed) Error() string {
	return "REST client is closed"
}

// ErrNotImplemented indicates a method is not implemented for REST transport.
type ErrNotImplemented struct {
	Method string
}

// Error implements the error interface.
func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("method not implemented for REST transport: %s", e.Method)
}

// ErrUnexpectedReplyType indicates a custom REST response decoder received
// a reply message of an unexpected concrete type. This is a programming
// error in the adapter's method routing, not a wire failure.
type ErrUnexpectedReplyType struct {
	Method string
}

// Error implements the error interface.
func (e ErrUnexpectedReplyType) Error() string {
	return fmt.Sprintf("unexpected reply message type for gRPC method %s", e.Method)
}

// ErrUnexpectedRequestType indicates a custom REST request encoder received a
// request message of an unexpected concrete type. This is a programming error
// in the adapter's method routing, not a wire failure.
type ErrUnexpectedRequestType struct {
	Method string
}

// Error implements the error interface.
func (e ErrUnexpectedRequestType) Error() string {
	return fmt.Sprintf("unexpected request message type for gRPC method %s", e.Method)
}

// ErrDurationClearNotSupported indicates an UpdateIPAMPool request asked to
// set a pool duration to zero. The REST pool update keeps any duration it
// is not given a positive value for, so the request cannot be carried.
type ErrDurationClearNotSupported struct {
	Field string
}

// Error implements the error interface.
func (e ErrDurationClearNotSupported) Error() string {
	return fmt.Sprintf("REST cannot set %s to zero: the REST pool update keeps a zero duration (send -1 to keep it)", e.Field)
}

// ErrProfileConfigNotJSON indicates a DeviceProfile's config bytes are not a
// JSON document. The REST profile routes carry config as a JSON value, so
// bytes that are not JSON cannot be sent without corrupting them.
type ErrProfileConfigNotJSON struct{}

// Error implements the error interface.
func (e ErrProfileConfigNotJSON) Error() string {
	return "device profile config is not valid JSON; the REST transport sends it as a JSON value"
}

// ErrPCRDigestNotHex indicates a profile's PCR baseline carried a digest
// that is not hex, the encoding the device webservice uses for it.
type ErrPCRDigestNotHex struct {
	Index string
	Err   error
}

// Error implements the error interface.
func (e ErrPCRDigestNotHex) Error() string {
	return fmt.Sprintf("PCR %s baseline digest is not hex: %v", e.Index, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrPCRDigestNotHex) Unwrap() error {
	return e.Err
}

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

package protorest

import "fmt"

// ErrReadBodyFailed indicates the request body could not be read.
type ErrReadBodyFailed struct {
	Cause error
}

func (e *ErrReadBodyFailed) Error() string {
	if e.Cause == nil {
		return "failed to read request body"
	}
	return "failed to read request body: " + e.Cause.Error()
}

func (e *ErrReadBodyFailed) Unwrap() error { return e.Cause }

// ErrInvalidJSON indicates the request body did not contain valid JSON for
// the expected protobuf message.
type ErrInvalidJSON struct {
	Cause error
}

func (e *ErrInvalidJSON) Error() string {
	if e.Cause == nil {
		return "invalid request body"
	}
	return "invalid request body: " + e.Cause.Error()
}

func (e *ErrInvalidJSON) Unwrap() error { return e.Cause }

// ErrMarshalFailed indicates the response payload could not be marshalled.
type ErrMarshalFailed struct {
	Cause error
}

func (e *ErrMarshalFailed) Error() string {
	if e.Cause == nil {
		return "failed to encode response"
	}
	return "failed to encode response: " + e.Cause.Error()
}

func (e *ErrMarshalFailed) Unwrap() error { return e.Cause }

// ErrInvalidQuery is returned when a query string parameter cannot be parsed.
type ErrInvalidQuery struct {
	Name  string
	Value string
	Cause error
}

func (e *ErrInvalidQuery) Error() string {
	return fmt.Sprintf("invalid query parameter %q (%q): %v", e.Name, e.Value, e.Cause)
}

func (e *ErrInvalidQuery) Unwrap() error { return e.Cause }

// ErrUnknown represents an unexpected nil error reaching the helper layer.
type ErrUnknown struct{}

func (e *ErrUnknown) Error() string { return "unknown internal error" }

// ErrServiceUnavailable indicates a router was registered without a backing
// sdk/go service client (e.g. when the embedded adapter could not be wired).
type ErrServiceUnavailable struct {
	Service string
}

func (e *ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("%s service is not available", e.Service)
}

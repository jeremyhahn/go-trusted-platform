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

// Package embedded provides an in-process gRPC transport that bypasses
// the network by dispatching calls directly to registered service handlers.
package embedded

import "fmt"

// ErrNilRegistry indicates a nil ServiceRegistry was provided.
type ErrNilRegistry struct{}

// Error implements the error interface.
func (e ErrNilRegistry) Error() string {
	return "embedded transport: ServiceRegistry is nil"
}

// ErrNotConnected indicates an operation was attempted on a disconnected transport.
type ErrNotConnected struct{}

// Error implements the error interface.
func (e ErrNotConnected) Error() string {
	return "embedded transport: not connected"
}

// ErrMethodNotFound indicates a gRPC method was not found in the dispatch map.
type ErrMethodNotFound struct {
	Method string
}

// Error implements the error interface.
func (e ErrMethodNotFound) Error() string {
	return fmt.Sprintf("embedded transport: method not found: %s", e.Method)
}

// ErrTypeMismatch indicates a request type assertion failed.
type ErrTypeMismatch struct {
	Expected string
	Got      string
}

// Error implements the error interface.
func (e ErrTypeMismatch) Error() string {
	return fmt.Sprintf("embedded transport: type mismatch: expected %s, got %s", e.Expected, e.Got)
}

// ErrMarshalFailed indicates a proto marshal operation failed.
type ErrMarshalFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrMarshalFailed) Error() string {
	return fmt.Sprintf("embedded transport: marshal failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrMarshalFailed) Unwrap() error {
	return e.Err
}

// ErrUnmarshalFailed indicates a proto unmarshal operation failed.
type ErrUnmarshalFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrUnmarshalFailed) Error() string {
	return fmt.Sprintf("embedded transport: unmarshal failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrUnmarshalFailed) Unwrap() error {
	return e.Err
}

// ErrServiceNotRegistered indicates a specific service is not registered.
type ErrServiceNotRegistered struct {
	Service string
}

// Error implements the error interface.
func (e ErrServiceNotRegistered) Error() string {
	return fmt.Sprintf("embedded transport: service not registered: %s", e.Service)
}

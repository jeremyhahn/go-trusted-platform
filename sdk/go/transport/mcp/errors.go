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

// Package mcp provides the MCP transport adapter for the platform SDK.
package mcp

import "fmt"

// ErrClientClosed indicates the MCP client has been closed.
type ErrClientClosed struct{}

// Error implements the error interface.
func (e ErrClientClosed) Error() string {
	return "MCP client is closed"
}

// ErrRPCFailed represents a JSON-RPC call failure.
type ErrRPCFailed struct {
	Code    int
	Message string
	Data    interface{}
}

// Error implements the error interface.
func (e ErrRPCFailed) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("MCP RPC error %d: %s (data: %v)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("MCP RPC error %d: %s", e.Code, e.Message)
}

// ErrToolNotFound indicates a requested MCP tool was not found.
type ErrToolNotFound struct {
	Name string
}

// Error implements the error interface.
func (e ErrToolNotFound) Error() string {
	return fmt.Sprintf("MCP tool not found: %s", e.Name)
}

// ErrResourceNotFound indicates a requested MCP resource was not found.
type ErrResourceNotFound struct {
	URI string
}

// Error implements the error interface.
func (e ErrResourceNotFound) Error() string {
	return fmt.Sprintf("MCP resource not found: %s", e.URI)
}

// ErrMethodNotMapped indicates a gRPC method has no MCP tool mapping.
type ErrMethodNotMapped struct {
	Method string
}

// Error implements the error interface.
func (e ErrMethodNotMapped) Error() string {
	return fmt.Sprintf("gRPC method not mapped to MCP tool: %s", e.Method)
}

// ErrInvalidResponse indicates the MCP response was invalid.
type ErrInvalidResponse struct {
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidResponse) Error() string {
	return fmt.Sprintf("invalid MCP response: %s", e.Reason)
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

// ErrUnexpectedArgsType indicates a custom MCP argument builder received a
// request message of an unexpected concrete type. This is a programming
// error in the adapter's method routing, not a wire failure.
type ErrUnexpectedArgsType struct {
	Method string
}

// Error implements the error interface.
func (e ErrUnexpectedArgsType) Error() string {
	return fmt.Sprintf("unexpected request message type for gRPC method %s", e.Method)
}

// ErrUnexpectedReplyType indicates a custom MCP result decoder received a
// reply message of an unexpected concrete type. This is a programming
// error in the adapter's method routing, not a wire failure.
type ErrUnexpectedReplyType struct {
	Method string
}

// Error implements the error interface.
func (e ErrUnexpectedReplyType) Error() string {
	return fmt.Sprintf("unexpected reply message type for gRPC method %s", e.Method)
}

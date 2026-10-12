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

// Package quic provides the QUIC transport adapter for the platform SDK.
package quic

import "fmt"

// ErrClientClosed indicates the QUIC client has been closed.
type ErrClientClosed struct{}

// Error implements the error interface.
func (e ErrClientClosed) Error() string {
	return "QUIC client is closed"
}

// ErrStreamFailed represents a QUIC stream operation failure.
type ErrStreamFailed struct {
	Operation string
	Err       error
}

// Error implements the error interface.
func (e ErrStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream %s failed: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrStreamFailed) Unwrap() error {
	return e.Err
}

// ErrProtocolError represents a QUIC protocol error.
type ErrProtocolError struct {
	Status  byte
	Message string
}

// Error implements the error interface.
func (e ErrProtocolError) Error() string {
	return fmt.Sprintf("QUIC protocol error (status 0x%02X): %s", e.Status, e.Message)
}

// ErrEncodingFailed represents a payload encoding failure.
type ErrEncodingFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrEncodingFailed) Error() string {
	return fmt.Sprintf("failed to encode payload: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrEncodingFailed) Unwrap() error {
	return e.Err
}

// ErrDecodingFailed represents a payload decoding failure.
type ErrDecodingFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrDecodingFailed) Error() string {
	return fmt.Sprintf("failed to decode payload: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrDecodingFailed) Unwrap() error {
	return e.Err
}

// ErrMethodNotMapped indicates a gRPC method has no QUIC opcode mapping.
type ErrMethodNotMapped struct {
	Method string
}

// Error implements the error interface.
func (e ErrMethodNotMapped) Error() string {
	return fmt.Sprintf("gRPC method not mapped to QUIC opcode: %s", e.Method)
}

// ErrCategorySubOpcodeMissing indicates a gRPC method routes to a
// category opcode but has no entry in categorySubOpcodeMap. The QUIC
// adapter cannot prepend the required sub-opcode prefix without one,
// so the request would be rejected by the server's sub_opcode check.
type ErrCategorySubOpcodeMissing struct {
	Method string
	Opcode byte
}

// Error implements the error interface.
func (e ErrCategorySubOpcodeMissing) Error() string {
	return fmt.Sprintf("QUIC category opcode 0x%02X has no sub-opcode mapping for gRPC method %s", e.Opcode, e.Method)
}

// ErrInvalidReplyType indicates a category-opcode response decoder received
// a reply message of an unexpected concrete type. This is a programming
// error in the adapter's method routing, not a wire failure.
type ErrInvalidReplyType struct {
	Method string
}

// Error implements the error interface.
func (e ErrInvalidReplyType) Error() string {
	return fmt.Sprintf("unexpected reply message type for gRPC method %s", e.Method)
}

// ErrInvalidArgsType indicates a method request encoder received a request
// message of an unexpected concrete type. Like ErrInvalidReplyType, this is
// a programming error in the adapter's method routing.
type ErrInvalidArgsType struct {
	Method string
}

// Error implements the error interface.
func (e ErrInvalidArgsType) Error() string {
	return fmt.Sprintf("unexpected request message type for gRPC method %s", e.Method)
}

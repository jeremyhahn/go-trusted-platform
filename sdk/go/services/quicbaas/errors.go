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

package quicbaas

import "fmt"

// ErrNilSDKClient is returned when attempting to create a wrapper with a nil SDK client.
type ErrNilSDKClient struct{}

// Error implements the error interface.
func (e ErrNilSDKClient) Error() string {
	return "quicbaas: SDK client cannot be nil"
}

// ErrClientClosed is returned when operations are attempted on a closed client.
type ErrClientClosed struct{}

// Error implements the error interface.
func (e ErrClientClosed) Error() string {
	return "quicbaas: client is closed"
}

// ErrClientCreationFailed is returned when the QuicBaaS SDK client fails to initialize.
type ErrClientCreationFailed struct {
	Address string
	Cause   error
}

// Error implements the error interface.
func (e ErrClientCreationFailed) Error() string {
	return fmt.Sprintf("quicbaas: failed to create client for address %s: %v", e.Address, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrClientCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidTransport is returned when an invalid transport type is specified.
type ErrInvalidTransport struct {
	Transport int
}

// Error implements the error interface.
func (e ErrInvalidTransport) Error() string {
	return fmt.Sprintf("quicbaas: invalid transport type: %d", e.Transport)
}

// ErrCloseFailed is returned when closing the client fails.
type ErrCloseFailed struct {
	Cause error
}

// Error implements the error interface.
func (e ErrCloseFailed) Error() string {
	return fmt.Sprintf("quicbaas: failed to close client: %v", e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrCloseFailed) Unwrap() error {
	return e.Cause
}

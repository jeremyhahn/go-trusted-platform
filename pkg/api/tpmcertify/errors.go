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

package tpmcertify

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrHandleRequired is returned when a Certify request names handle 0.
// It is InvalidArgument on every transport.
type ErrHandleRequired struct{}

// Error returns the message.
func (ErrHandleRequired) Error() string { return "key handle is required" }

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrHandleRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrHandleNotPersistent is returned when the key handle is outside the
// persistent range 0x81000000-0x81FFFFFF. A transient key needs its blob and
// full key attributes to be loaded, which a handle alone does not carry.
// It is InvalidArgument on every transport.
type ErrHandleNotPersistent struct {
	Handle uint32
}

// Error returns the message.
func (e ErrHandleNotPersistent) Error() string {
	return fmt.Sprintf("key handle 0x%08X is not a persistent handle (0x%08X-0x%08X)",
		e.Handle, persistentFirst, persistentLast)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrHandleNotPersistent) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrNonceTooLarge is returned when the qualifying data exceeds what a
// TPM2B_DATA carries. It is InvalidArgument on every transport.
type ErrNonceTooLarge struct {
	Size int
}

// Error returns the message.
func (e ErrNonceTooLarge) Error() string {
	return fmt.Sprintf("nonce is %d bytes, at most %d are allowed", e.Size, MaxNonceSize)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrNonceTooLarge) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrTPMUnavailable is returned when no TPM is configured. It is Unavailable
// on every transport.
type ErrTPMUnavailable struct{}

// Error returns the message.
func (ErrTPMUnavailable) Error() string { return "TPM not available" }

// GRPCStatus classifies the error as Unavailable.
func (e ErrTPMUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrKeyNotFound is returned when no object is loaded at the persistent
// handle. It is NotFound on every transport.
type ErrKeyNotFound struct {
	Handle uint32
}

// Error returns the message.
func (e ErrKeyNotFound) Error() string {
	return fmt.Sprintf("no key at handle 0x%08X", e.Handle)
}

// GRPCStatus classifies the error as NotFound.
func (e ErrKeyNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrCertifyFailed wraps any other failure of the SDK's TPM2_Certify. It is
// Internal on every transport.
type ErrCertifyFailed struct {
	Cause error
}

// Error returns the message.
func (e ErrCertifyFailed) Error() string { return "TPM2_Certify failed: " + e.Cause.Error() }

// Unwrap returns the SDK error.
func (e ErrCertifyFailed) Unwrap() error { return e.Cause }

// GRPCStatus classifies the error as Internal.
func (e ErrCertifyFailed) GRPCStatus() *status.Status {
	return status.New(codes.Internal, e.Error())
}

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

package orchestrator

import (
	"errors"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// ErrNotConfigured reports that the daemon has no go-quicbaas orchestrator
// client: the embedded SDK is not running on this node.
type ErrNotConfigured struct{}

func (ErrNotConfigured) Error() string {
	return "orchestrator: the go-quicbaas orchestrator client is not configured on this node"
}

// ErrMissingField reports a request that lacks a required field.
type ErrMissingField struct {
	Field string
}

func (e *ErrMissingField) Error() string {
	return "orchestrator: " + e.Field + " is required"
}

// ErrInvalidPage reports a negative page limit or offset.
type ErrInvalidPage struct{}

func (ErrInvalidPage) Error() string {
	return "orchestrator: page limit and offset must not be negative"
}

// OperationError wraps an error the go-quicbaas orchestrator returned, naming
// the operation that failed. Unwrap exposes the SDK error to Classify.
type OperationError struct {
	Op  string
	Err error
}

func (e *OperationError) Error() string {
	return "orchestrator: " + e.Op + ": " + e.Err.Error()
}

func (e *OperationError) Unwrap() error {
	return e.Err
}

// ErrorKind is the transport-neutral class of a service error. Every
// transport maps a kind to its own status: a gRPC code, an HTTP status, an
// MCP or QUIC error code.
type ErrorKind int

const (
	// KindInternal is any error not classified below.
	KindInternal ErrorKind = iota
	KindInvalidArgument
	KindNotFound
	KindConflict
	KindPermissionDenied
	KindUnauthenticated
	KindUnavailable
)

// sdkKinds classifies go-quicbaas SDK errors, checked in order.
var sdkKinds = []struct {
	is   func(error) bool
	kind ErrorKind
}{
	{sdkerrors.IsInvalidInput, KindInvalidArgument},
	{sdkerrors.IsNotFound, KindNotFound},
	{sdkerrors.IsConflict, KindConflict},
	{sdkerrors.IsAlreadyExists, KindConflict},
	{sdkerrors.IsForbidden, KindPermissionDenied},
	{sdkerrors.IsUnauthorized, KindUnauthenticated},
	{sdkerrors.IsUnavailable, KindUnavailable},
}

// Classify returns the kind of err.
func Classify(err error) ErrorKind {
	var missing *ErrMissingField
	switch {
	case errors.As(err, &missing), errors.Is(err, ErrInvalidPage{}):
		return KindInvalidArgument
	case errors.Is(err, ErrNotConfigured{}):
		return KindUnavailable
	}
	for _, entry := range sdkKinds {
		if entry.is(err) {
			return entry.kind
		}
	}
	return KindInternal
}

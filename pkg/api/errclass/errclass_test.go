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

package errclass

import (
	"errors"
	"net/http"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// classedError carries its class the way the platform's typed errors do.
type classedError struct{ class codes.Code }

func (e classedError) Error() string { return "classed: " + e.class.String() }

func (e classedError) GRPCStatus() *status.Status { return status.New(e.class, e.Error()) }

// wrapper hides its cause one level down, as the daemon's
// ErrKMSOperationFailed does.
type wrapper struct{ cause error }

func (e wrapper) Error() string { return "wrapped: " + e.cause.Error() }

func (e wrapper) Unwrap() error { return e.cause }

func TestCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"nil", nil, codes.OK},
		{"status error", status.Error(codes.NotFound, "gone"), codes.NotFound},
		{"typed error with GRPCStatus", classedError{codes.InvalidArgument}, codes.InvalidArgument},
		{"wrapped typed error", wrapper{classedError{codes.PermissionDenied}}, codes.PermissionDenied},
		{"sdk invalid input", sdkerrors.NewInvalidInput("op", "bad"), codes.InvalidArgument},
		{"sdk not found", sdkerrors.NewNotFound("op", "gone"), codes.NotFound},
		{"sdk already exists", sdkerrors.NewAlreadyExists("op", "dup"), codes.AlreadyExists},
		{"sdk precondition", sdkerrors.NewPreconditionFailed("op", "state"), codes.FailedPrecondition},
		{"sdk not initialized", sdkerrors.NewNotInitialized("op", "init"), codes.FailedPrecondition},
		{"sdk forbidden", sdkerrors.NewForbidden("op", "no"), codes.PermissionDenied},
		{"sdk unauthorized", sdkerrors.NewUnauthorized("op", "who"), codes.Unauthenticated},
		{"sdk unimplemented", sdkerrors.NewUnimplemented("op", "later"), codes.Unimplemented},
		{"sdk unavailable", sdkerrors.NewUnavailable("op", "down"), codes.Unavailable},
		{"sdk sealed", sdkerrors.NewSealed("op", "sealed"), codes.Unavailable},
		{"sdk connection", sdkerrors.NewConnection("op", "dial"), codes.Unavailable},
		{"wrapped sdk error", wrapper{sdkerrors.NewNotFound("op", "gone")}, codes.NotFound},
		{"database not found", quicbaas.NewDatabaseError(quicbaas.ErrNotFound, "op", "gone"), codes.NotFound},
		{"database conflict", quicbaas.NewDatabaseError(quicbaas.ErrConflict, "op", "dup"), codes.AlreadyExists},
		{"database timeout", quicbaas.NewDatabaseError(quicbaas.ErrTimeout, "op", "slow"), codes.DeadlineExceeded},
		{"database unavailable", quicbaas.NewDatabaseError(quicbaas.ErrUnavailable, "op", "down"), codes.Unavailable},
		{"wrapped database error", wrapper{quicbaas.NewDatabaseError(quicbaas.ErrNotFound, "op", "gone")}, codes.NotFound},
		{"embedded unknown method", embedded.NewUnknownMethodError("quicbaas.Secrets", "Rotate"), codes.Unimplemented},
		{"wrapped embedded unknown method", wrapper{embedded.NewUnknownMethodError("quicbaas.Secrets", "Rotate")}, codes.Unimplemented},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Code(tt.err); got != tt.want {
				t.Errorf("Code(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestCode_UnknownStaysInternal covers every error that names no class:
// it is Internal, never guessed from its message.
func TestCode_UnknownStaysInternal(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"plain error", errors.New("key not found")},
		{"status Unknown", status.Error(codes.Unknown, "not found")},
		{"sdk internal", sdkerrors.NewInternal("op", "boom")},
		{"sdk unknown code", sdkerrors.New(sdkerrors.CodeUnknown, "op", "not found")},
		{"database internal", quicbaas.NewDatabaseError(quicbaas.ErrInternal, "op", "boom")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Code(tt.err); got != codes.Internal {
				t.Errorf("Code(%v) = %v, want Internal", tt.err, got)
			}
		})
	}
}

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		class codes.Code
		want  int
	}{
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.Unauthenticated, http.StatusUnauthorized},
		{codes.PermissionDenied, http.StatusForbidden},
		{codes.NotFound, http.StatusNotFound},
		{codes.AlreadyExists, http.StatusConflict},
		{codes.Aborted, http.StatusConflict},
		{codes.FailedPrecondition, http.StatusConflict},
		{codes.ResourceExhausted, http.StatusTooManyRequests},
		{codes.Unimplemented, http.StatusNotImplemented},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.DeadlineExceeded, http.StatusGatewayTimeout},
		{codes.Internal, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.class.String(), func(t *testing.T) {
			if got := HTTPStatus(classedError{tt.class}); got != tt.want {
				t.Errorf("HTTPStatus(%v) = %d, want %d", tt.class, got, tt.want)
			}
		})
	}
}

func TestHTTPStatus_UnknownIsInternalServerError(t *testing.T) {
	if got := HTTPStatus(errors.New("key not found")); got != http.StatusInternalServerError {
		t.Errorf("HTTPStatus(unclassified) = %d, want %d", got, http.StatusInternalServerError)
	}
}

func TestQUICStatus(t *testing.T) {
	tests := []struct {
		class codes.Code
		want  byte
	}{
		{codes.InvalidArgument, quicwire.StatusInvalidArgument},
		{codes.Unauthenticated, quicwire.StatusUnauthorized},
		{codes.PermissionDenied, quicwire.StatusPermissionDenied},
		{codes.NotFound, quicwire.StatusNotFound},
		{codes.AlreadyExists, quicwire.StatusAlreadyExists},
		{codes.Aborted, quicwire.StatusAlreadyExists},
		{codes.FailedPrecondition, quicwire.StatusFailedPrecondition},
		{codes.ResourceExhausted, quicwire.StatusResourceExhausted},
		{codes.Unimplemented, quicwire.StatusNotImplemented},
		{codes.Unavailable, quicwire.StatusUnavailable},
		{codes.DeadlineExceeded, quicwire.StatusTimeout},
		{codes.Internal, quicwire.StatusInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.class.String(), func(t *testing.T) {
			if got := QUICStatus(classedError{tt.class}); got != tt.want {
				t.Errorf("QUICStatus(%v) = %#x, want %#x", tt.class, got, tt.want)
			}
		})
	}
}

func TestQUICStatus_UnknownIsInternalError(t *testing.T) {
	if got := QUICStatus(errors.New("key not found")); got != quicwire.StatusInternalError {
		t.Errorf("QUICStatus(unclassified) = %#x, want %#x", got, quicwire.StatusInternalError)
	}
}

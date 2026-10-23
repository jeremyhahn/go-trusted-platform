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

package barrier

import (
	"context"
	"errors"
	"fmt"
	"testing"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCode_Nil(t *testing.T) {
	if got := Code(nil); got != codes.OK {
		t.Fatalf("Code(nil) = %v, want OK", got)
	}
}

func TestCode_Sentinels(t *testing.T) {
	tests := []struct {
		err  error
		want codes.Code
	}{
		{ErrAlreadyInitialized, codes.AlreadyExists},
		{ErrNotInitialized, codes.FailedPrecondition},
		{ErrSealed, codes.FailedPrecondition},
		{ErrNotSealed, codes.FailedPrecondition},
		{ErrCeremonyNotSupported, codes.FailedPrecondition},
		{ErrEmptySecret, codes.InvalidArgument},
		{ErrEmptyShare, codes.InvalidArgument},
		{ErrInvalidThreshold, codes.InvalidArgument},
		{ErrNilContext, codes.InvalidArgument},
		{ErrEmptyUsername, codes.InvalidArgument},
		{ErrEmptyNonce, codes.InvalidArgument},
		{ErrEmptySignature, codes.InvalidArgument},
		{ErrNilSDKClient, codes.Internal},
		{ErrNilConfig, codes.Internal},
		{context.Canceled, codes.Canceled},
		{context.DeadlineExceeded, codes.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			wrapped := map[string]error{
				"bare":          tt.err,
				"fmt_wrapped":   fmt.Errorf("handler: %w", tt.err),
				"manager_error": &ManagerError{Op: "Unseal", Err: fmt.Errorf("transport: %w", tt.err)},
				"joined":        errors.Join(errors.New("cleanup failed"), tt.err),
			}
			for name, err := range wrapped {
				if got := Code(err); got != tt.want {
					t.Errorf("%s: Code(%v) = %v, want %v", name, err, got, tt.want)
				}
			}
		})
	}
}

func TestCode_UpstreamGRPCStatus(t *testing.T) {
	tests := []struct {
		name string
		code codes.Code
		want codes.Code
	}{
		{"permission_denied", codes.PermissionDenied, codes.PermissionDenied},
		{"invalid_argument", codes.InvalidArgument, codes.InvalidArgument},
		{"failed_precondition", codes.FailedPrecondition, codes.FailedPrecondition},
		{"unavailable", codes.Unavailable, codes.Unavailable},
		{"unknown_is_internal", codes.Unknown, codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ManagerError{
				Op:  "Unseal",
				Err: fmt.Errorf("grpc transport: %w", status.Error(tt.code, "upstream")),
			}
			if got := Code(err); got != tt.want {
				t.Errorf("Code(%v) = %v, want %v", err, got, tt.want)
			}
		})
	}
}

func TestCode_QuicBaaSErrors(t *testing.T) {
	tests := []struct {
		code sdkerrors.ErrorCode
		want codes.Code
	}{
		{sdkerrors.CodeInvalidInput, codes.InvalidArgument},
		{sdkerrors.CodeNotFound, codes.NotFound},
		{sdkerrors.CodeAlreadyExists, codes.AlreadyExists},
		{sdkerrors.CodeConflict, codes.AlreadyExists},
		{sdkerrors.CodeUnauthorized, codes.Unauthenticated},
		{sdkerrors.CodeForbidden, codes.PermissionDenied},
		{sdkerrors.CodePreconditionFailed, codes.FailedPrecondition},
		{sdkerrors.CodeSealed, codes.FailedPrecondition},
		{sdkerrors.CodeNotInitialized, codes.FailedPrecondition},
		{sdkerrors.CodeRateLimited, codes.ResourceExhausted},
		{sdkerrors.CodeResourceExhausted, codes.ResourceExhausted},
		{sdkerrors.CodeUnavailable, codes.Unavailable},
		{sdkerrors.CodeConnection, codes.Unavailable},
		{sdkerrors.CodeTransport, codes.Unavailable},
		{sdkerrors.CodeTimeout, codes.DeadlineExceeded},
		{sdkerrors.CodeCanceled, codes.Canceled},
		{sdkerrors.CodeUnimplemented, codes.Unimplemented},
		{sdkerrors.CodeInternal, codes.Internal},
		{sdkerrors.CodeConfiguration, codes.Internal},
		{sdkerrors.CodeUnknown, codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			err := &ManagerError{
				Op:  "Status",
				Err: fmt.Errorf("security client: %w", sdkerrors.New(tt.code, "buildQRDBClient", "upstream")),
			}
			if got := Code(err); got != tt.want {
				t.Errorf("Code(%v) = %v, want %v", err, got, tt.want)
			}
		})
	}
}

func TestCode_UnclassifiedIsInternal(t *testing.T) {
	tests := map[string]error{
		"plain":         errors.New("disk on fire"),
		"manager_error": &ManagerError{Op: "Seal", Err: errors.New("disk on fire")},
		"config_error":  fmt.Errorf("startup: %w", &ConfigError{Field: "SealStrategy", Message: "invalid"}),
	}

	for name, err := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Code(err); got != codes.Internal {
				t.Errorf("Code(%v) = %v, want Internal", err, got)
			}
		})
	}
}

func TestSDKCode(t *testing.T) {
	code, ok := SDKCode(fmt.Errorf("get job: %w", sdkerrors.NewNotFound("GetJob", "no job 7")))
	if !ok || code != codes.NotFound {
		t.Errorf("SDKCode(wrapped NotFound) = %v, %v; want NotFound, true", code, ok)
	}

	unclassified := map[string]error{
		"no sdk error":    errors.New("disk on fire"),
		"grpc status":     status.Error(codes.NotFound, "gone"),
		"unlisted code":   &sdkerrors.QBError{Code: sdkerrors.ErrorCode(-1), Message: "?"},
		"nil error chain": nil,
	}
	for name, err := range unclassified {
		if code, ok := SDKCode(err); ok {
			t.Errorf("%s: SDKCode = %v, true; want false", name, code)
		}
	}
}

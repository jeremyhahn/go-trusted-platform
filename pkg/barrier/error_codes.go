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

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sentinelCodes classifies the barrier sentinels and the context errors.
// The Manager returns its local pre-check failures bare and every upstream
// failure wrapped in a ManagerError, so a chain carries at most one of them.
var sentinelCodes = map[error]codes.Code{
	ErrAlreadyInitialized:    codes.AlreadyExists,
	ErrNotInitialized:        codes.FailedPrecondition,
	ErrSealed:                codes.FailedPrecondition,
	ErrNotSealed:             codes.FailedPrecondition,
	ErrCeremonyNotSupported:  codes.FailedPrecondition,
	ErrEmptySecret:           codes.InvalidArgument,
	ErrEmptyShare:            codes.InvalidArgument,
	ErrInvalidThreshold:      codes.InvalidArgument,
	ErrNilContext:            codes.InvalidArgument,
	ErrEmptyUsername:         codes.InvalidArgument,
	ErrEmptyNonce:            codes.InvalidArgument,
	ErrEmptySignature:        codes.InvalidArgument,
	ErrNilSDKClient:          codes.Internal,
	ErrNilConfig:             codes.Internal,
	context.Canceled:         codes.Canceled,
	context.DeadlineExceeded: codes.DeadlineExceeded,
}

// quicbaasCodes classifies the quicbaas SDK error codes, which the SDK
// returns when it cannot build the security client. Conflict collapses
// into AlreadyExists, as the handbook's gRPC mapping does.
var quicbaasCodes = map[sdkerrors.ErrorCode]codes.Code{
	sdkerrors.CodeInvalidInput:       codes.InvalidArgument,
	sdkerrors.CodeNotFound:           codes.NotFound,
	sdkerrors.CodeAlreadyExists:      codes.AlreadyExists,
	sdkerrors.CodeConflict:           codes.AlreadyExists,
	sdkerrors.CodeUnauthorized:       codes.Unauthenticated,
	sdkerrors.CodeForbidden:          codes.PermissionDenied,
	sdkerrors.CodePreconditionFailed: codes.FailedPrecondition,
	sdkerrors.CodeSealed:             codes.FailedPrecondition,
	sdkerrors.CodeNotInitialized:     codes.FailedPrecondition,
	sdkerrors.CodeRateLimited:        codes.ResourceExhausted,
	sdkerrors.CodeResourceExhausted:  codes.ResourceExhausted,
	sdkerrors.CodeUnavailable:        codes.Unavailable,
	sdkerrors.CodeConnection:         codes.Unavailable,
	sdkerrors.CodeTransport:          codes.Unavailable,
	sdkerrors.CodeTimeout:            codes.DeadlineExceeded,
	sdkerrors.CodeCanceled:           codes.Canceled,
	sdkerrors.CodeUnimplemented:      codes.Unimplemented,
	sdkerrors.CodeInternal:           codes.Internal,
	sdkerrors.CodeConfiguration:      codes.Internal,
}

// Code classifies a barrier error for every transport. It looks through
// the whole error chain, in this order:
//
//   - a barrier sentinel or a context error, by sentinelCodes;
//   - a gRPC status from the upstream gRPC transport, by its own code,
//     unless that code is OK or Unknown;
//   - a quicbaas SDK error, by quicbaasCodes.
//
// Anything else is Internal, and a nil error is OK.
func Code(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	for sentinel, code := range sentinelCodes {
		if errors.Is(err, sentinel) {
			return code
		}
	}
	var grpcErr interface{ GRPCStatus() *status.Status }
	if errors.As(err, &grpcErr) {
		if code := grpcErr.GRPCStatus().Code(); code != codes.OK && code != codes.Unknown {
			return code
		}
	}
	var qbErr *sdkerrors.QBError
	if errors.As(err, &qbErr) {
		if code, ok := quicbaasCodes[qbErr.Code]; ok {
			return code
		}
	}
	return codes.Internal
}

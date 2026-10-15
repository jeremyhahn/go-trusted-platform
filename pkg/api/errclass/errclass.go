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

// Package errclass is the one classifier the platform API transports share:
// it names the class of an error as a gRPC status code, so gRPC, Unix, REST,
// QUIC and MCP answer the same error with the same class. The class comes
// from the error's type, never from its message; an error that names no
// class is Internal.
package errclass

import (
	"net/http"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// classifiers are tried in order; the first that recognises the error
// decides its class.
var classifiers = []func(error) (codes.Code, bool){
	statusClass,
	sdkClass,
	databaseClass,
}

// sdkClasses classifies the QuicBaaS SDK error codes.
var sdkClasses = map[sdkerrors.ErrorCode]codes.Code{
	sdkerrors.CodeInvalidInput:       codes.InvalidArgument,
	sdkerrors.CodeNotFound:           codes.NotFound,
	sdkerrors.CodeAlreadyExists:      codes.AlreadyExists,
	sdkerrors.CodeUnauthorized:       codes.Unauthenticated,
	sdkerrors.CodeForbidden:          codes.PermissionDenied,
	sdkerrors.CodeConflict:           codes.Aborted,
	sdkerrors.CodePreconditionFailed: codes.FailedPrecondition,
	sdkerrors.CodeRateLimited:        codes.ResourceExhausted,
	sdkerrors.CodeUnavailable:        codes.Unavailable,
	sdkerrors.CodeTimeout:            codes.DeadlineExceeded,
	sdkerrors.CodeCanceled:           codes.Canceled,
	sdkerrors.CodeUnimplemented:      codes.Unimplemented,
	sdkerrors.CodeResourceExhausted:  codes.ResourceExhausted,
	sdkerrors.CodeSealed:             codes.Unavailable,
	sdkerrors.CodeNotInitialized:     codes.FailedPrecondition,
	sdkerrors.CodeConnection:         codes.Unavailable,
	sdkerrors.CodeTransport:          codes.Unavailable,
}

// databaseClasses classifies a database error by the HTTP status its own
// code reports. The SDK names only five database error codes, so the
// code's HTTPStatus is the one typed classification that covers them all.
var databaseClasses = map[int]codes.Code{
	http.StatusBadRequest:          codes.InvalidArgument,
	http.StatusUnauthorized:        codes.Unauthenticated,
	http.StatusForbidden:           codes.PermissionDenied,
	http.StatusNotFound:            codes.NotFound,
	http.StatusRequestTimeout:      codes.DeadlineExceeded,
	http.StatusConflict:            codes.AlreadyExists,
	http.StatusPreconditionFailed:  codes.FailedPrecondition,
	http.StatusTooManyRequests:     codes.ResourceExhausted,
	http.StatusNotImplemented:      codes.Unimplemented,
	http.StatusServiceUnavailable:  codes.Unavailable,
	http.StatusInternalServerError: codes.Internal,
}

// httpStatuses is the REST answer for each class; the platform SDK's REST
// transport decodes these back to the same class.
var httpStatuses = map[codes.Code]int{
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.Unauthenticated:    http.StatusUnauthorized,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.NotFound:           http.StatusNotFound,
	codes.AlreadyExists:      http.StatusConflict,
	codes.Aborted:            http.StatusConflict,
	codes.FailedPrecondition: http.StatusPreconditionFailed,
	codes.ResourceExhausted:  http.StatusTooManyRequests,
	codes.Unimplemented:      http.StatusNotImplemented,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.DeadlineExceeded:   http.StatusGatewayTimeout,
}

// quicStatuses is the QUIC answer for each class. QUIC has no conflict
// status, so Aborted answers as AlreadyExists.
var quicStatuses = map[codes.Code]byte{
	codes.InvalidArgument:    quicwire.StatusInvalidArgument,
	codes.Unauthenticated:    quicwire.StatusUnauthorized,
	codes.PermissionDenied:   quicwire.StatusPermissionDenied,
	codes.NotFound:           quicwire.StatusNotFound,
	codes.AlreadyExists:      quicwire.StatusAlreadyExists,
	codes.Aborted:            quicwire.StatusAlreadyExists,
	codes.FailedPrecondition: quicwire.StatusFailedPrecondition,
	codes.ResourceExhausted:  quicwire.StatusResourceExhausted,
	codes.Unimplemented:      quicwire.StatusNotImplemented,
	codes.Unavailable:        quicwire.StatusUnavailable,
	codes.DeadlineExceeded:   quicwire.StatusTimeout,
}

// Code returns the class of err: OK for nil, Internal for an error that
// names no class.
func Code(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	for _, classify := range classifiers {
		if class, ok := classify(err); ok {
			return class
		}
	}
	return codes.Internal
}

// HTTPStatus returns the REST status for the class of err.
func HTTPStatus(err error) int {
	if httpStatus, ok := httpStatuses[Code(err)]; ok {
		return httpStatus
	}
	return http.StatusInternalServerError
}

// QUICStatus returns the QUIC status for the class of err.
func QUICStatus(err error) byte {
	if quicStatus, ok := quicStatuses[Code(err)]; ok {
		return quicStatus
	}
	return quicwire.StatusInternalError
}

// statusClass classifies a gRPC status error, or any error in whose chain
// a typed error reports its class through GRPCStatus.
func statusClass(err error) (codes.Code, bool) {
	st, ok := status.FromError(err)
	if !ok {
		return codes.Unknown, false
	}
	class := st.Code()
	return class, class != codes.Unknown && class != codes.OK
}

// sdkClass classifies a QuicBaaS SDK error by its code.
func sdkClass(err error) (codes.Code, bool) {
	class, ok := sdkClasses[sdkerrors.Code(err)]
	return class, ok
}

// databaseClass classifies a database error, which the SDK's embedded
// transport passes through from the QuicBaaS services unconverted.
func databaseClass(err error) (codes.Code, bool) {
	var dbErr *quicbaas.DatabaseError
	if !quicbaas.IsDatabaseError(err, &dbErr) {
		return codes.Unknown, false
	}
	class, ok := databaseClasses[dbErr.Code.HTTPStatus()]
	return class, ok
}

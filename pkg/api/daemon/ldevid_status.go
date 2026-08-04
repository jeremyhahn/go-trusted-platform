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

package daemon

import (
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrLDevIDServiceNotConfigured is returned by a transport handler when the
// shared IDevIDGRPCService has not been injected, so LDevID (802.1AR)
// issuance cannot be served on that protocol.
type ErrLDevIDServiceNotConfigured struct{}

// Error implements the error interface.
func (ErrLDevIDServiceNotConfigured) Error() string {
	return "idevid: LDevID service not configured for this transport"
}

// ldevidGRPCToHTTPStatus maps a gRPC status error returned by
// IDevIDGRPCService.CreateLDevID to the closest HTTP status code so the REST
// transport reports the same failure class the gRPC transport does.
func ldevidGRPCToHTTPStatus(err error) int {
	switch status.Code(err) {
	case codes.OK:
		return http.StatusOK
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.NotFound:
		return http.StatusNotFound
	case codes.AlreadyExists:
		return http.StatusConflict
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// ldevidGRPCToQUICStatus maps a gRPC status error returned by
// IDevIDGRPCService.CreateLDevID to the closest QUIC status byte so the QUIC
// transport reports the same failure class the gRPC transport does.
func ldevidGRPCToQUICStatus(err error) byte {
	switch status.Code(err) {
	case codes.OK:
		return quic.StatusOK
	case codes.InvalidArgument, codes.FailedPrecondition:
		return quic.StatusInvalidArgument
	case codes.NotFound:
		return quic.StatusNotFound
	case codes.AlreadyExists:
		return quic.StatusAlreadyExists
	case codes.PermissionDenied:
		return quic.StatusPermissionDenied
	case codes.Unauthenticated:
		return quic.StatusUnauthorized
	case codes.Unavailable:
		return quic.StatusUnavailable
	default:
		return quic.StatusInternalError
	}
}

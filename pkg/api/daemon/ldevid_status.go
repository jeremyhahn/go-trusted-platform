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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

// idevidGRPCToHTTPStatus maps a gRPC status error returned by
// IDevIDGRPCService (LDevID issuance, and the IDevID and IAK key-delete
// refusal) to the closest HTTP status code so the REST transport reports the
// same failure class the gRPC transport does.
func idevidGRPCToHTTPStatus(err error) int {
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

// idevidGRPCToQUICStatus maps a gRPC status error returned by
// IDevIDGRPCService (LDevID issuance, and the IDevID and IAK key-delete
// refusal) to the closest QUIC status byte so the QUIC transport reports the
// same failure class the gRPC transport does.
func idevidGRPCToQUICStatus(err error) byte {
	switch status.Code(err) {
	case codes.OK:
		return quicwire.StatusOK
	case codes.InvalidArgument:
		return quicwire.StatusInvalidArgument
	case codes.FailedPrecondition:
		return quicwire.StatusFailedPrecondition
	case codes.NotFound:
		return quicwire.StatusNotFound
	case codes.AlreadyExists:
		return quicwire.StatusAlreadyExists
	case codes.PermissionDenied:
		return quicwire.StatusPermissionDenied
	case codes.Unauthenticated:
		return quicwire.StatusUnauthorized
	case codes.Unavailable:
		return quicwire.StatusUnavailable
	default:
		return quicwire.StatusInternalError
	}
}

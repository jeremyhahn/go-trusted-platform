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
	"context"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// RecoveryUnaryInterceptor returns a gRPC unary server interceptor that
// recovers from panics in downstream interceptors and handlers, converting
// them into a codes.Internal error rather than crashing the daemon process.
//
// gRPC, unlike net/http and the QUIC transport, does not recover handler
// panics on its own — an un-recovered panic in any handler propagates up the
// goroutine and terminates the entire server. This interceptor is chained
// first (outermost) so it wraps the authentication interceptors as well.
func RecoveryUnaryInterceptor(logger *logging.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// RecoveryStreamInterceptor returns a gRPC stream server interceptor that
// recovers from panics for the same reasons as RecoveryUnaryInterceptor.
func RecoveryStreamInterceptor(logger *logging.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}

// logPanic records a recovered handler panic with its stack trace.
func logPanic(logger *logging.Logger, method string, r interface{}) {
	if logger == nil {
		return
	}
	logger.Errorf("grpc: recovered panic serving %s: %v\n%s", method, r, debug.Stack())
}

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
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// ErrUnixCallerNotRoot is returned when a non-root peer calls a root-only
// method over the daemon's Unix gRPC socket.
type ErrUnixCallerNotRoot struct {
	Method string
	UID    uint32
}

func (e ErrUnixCallerNotRoot) Error() string {
	return e.Method + " over the Unix socket requires root, but the caller is uid " + strconv.FormatUint(uint64(e.UID), 10)
}

// unixRootOnlyMethods are the CA lifecycle RPCs. On the network transports
// they need the ca:create / trust:write scopes; on the Unix socket, which has
// no scope check, they need a root peer, as SignCSR does in
// grpcapi.AuthorizeSignCSR.
var unixRootOnlyMethods = map[string]struct{}{
	"/platform.v1.CAService/InitCA":                  {},
	"/platform.v1.CAService/InstallCACertificates":   {},
	"/platform.v1.CAService/UninstallCACertificates": {},
}

// UnixRootOnlyUnaryInterceptor refuses a non-root peer on the root-only
// methods of the Unix gRPC socket and passes every other method through. It
// must run after peercred.UnixCredentialsUnaryInterceptor; a call with no
// Unix credentials in its context is refused.
func UnixRootOnlyUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := unixRootOnlyMethods[info.FullMethod]; !ok {
			return handler(ctx, req)
		}
		creds, ok := peercred.UnixCredentialsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, info.FullMethod+": no Unix peer credentials")
		}
		if !creds.IsRoot() {
			return nil, status.Error(codes.PermissionDenied,
				ErrUnixCallerNotRoot{Method: info.FullMethod, UID: creds.UID}.Error())
		}
		return handler(ctx, req)
	}
}

// unixGRPCServerOptions returns the options of the daemon's Unix gRPC server:
// peer-credential transport, recovery, the Unix credentials interceptors and,
// last, the root-only guard (it reads the credentials those put in the context).
func unixGRPCServerOptions(logger *logging.Logger) []grpc.ServerOption {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return []grpc.ServerOption{
		grpc.Creds(peercred.NewUnixTransportCredentials()),
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(logger)),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(logger)),
		grpc.ChainUnaryInterceptor(peercred.UnixCredentialsUnaryInterceptor()),
		grpc.ChainStreamInterceptor(peercred.UnixCredentialsStreamInterceptor()),
		grpc.ChainUnaryInterceptor(UnixRootOnlyUnaryInterceptor()),
	}
}

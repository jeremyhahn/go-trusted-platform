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
	"net"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	platformiam "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
)

// The callers below are the identities the daemon's transports hand a
// service once a request is authenticated (#646): a tenant-bound platform
// token on QUIC or MCP, or the kernel-verified Unix-socket operator. Tests
// call as one of them; a bare context.Background() is the unbound caller
// the services refuse (TestUnboundCallerIsRefusedOnEveryTransport).

// quicTenantCaller is the context the QUIC server gives a request that
// carries a validated platform token bound to tenantID.
func quicTenantCaller(tenantID string) context.Context {
	return quic.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
}

// mcpTenantCaller is the context the MCP server gives a tool call that
// carries a validated platform token bound to tenantID.
func mcpTenantCaller(tenantID string) context.Context {
	return mcp.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID})
}

// asUnixOperator attaches the Unix-socket operator's peer credentials to ctx,
// as the Unix-socket server's interceptor does.
func asUnixOperator(ctx context.Context) context.Context {
	return peercred.ContextWithUnixCredentials(ctx, peercred.UnixCredentials{PID: 1, UID: 0, GID: 0})
}

// unixOperatorGRPCOption makes a test gRPC server serve every unary call as
// the Unix-socket operator.
func unixOperatorGRPCOption() grpc.ServerOption {
	return grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(asUnixOperator(ctx), req)
	})
}

// unixOperatorHTTP serves every request of next as the Unix-socket operator.
func unixOperatorHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(asUnixOperator(r.Context())))
	})
}

// iamOperatorGRPCClient is an SDK IAM client over a TLS gRPC server that
// serves svc as the Unix-socket operator.
func iamOperatorGRPCClient(t *testing.T, svc *IAMGRPCService) *platformiam.Client {
	tlsBundle := testutil.GenerateTestTLSBundle(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveGRPCServices(t, lis, func(srv grpc.ServiceRegistrar) {
		platformv1.RegisterPlatformIAMServiceServer(srv, svc)
	}, grpc.Creds(credentials.NewTLS(tlsBundle.ServerTLSConfig())), unixOperatorGRPCOption())
	adapter, err := sdkgrpc.Connect(context.Background(), platform.NewOptions(
		platform.WithGRPCAddr(lis.Addr().String()),
		platform.WithTLSConfig(tlsBundle.ClientTLSConfig()),
	))
	return iamClient(connection(t, adapter, err))
}

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

//go:build codec_msgpack

package daemon

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	platformiam "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
)

// iamOperatorGRPCClient is an SDK IAM client over a TLS gRPC server that
// serves svc as the Unix-socket operator. It lives apart from the untagged
// caller helpers (caller_identity_test.go) because serveGRPCServices,
// connection and iamClient are built only with codec_msgpack.
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

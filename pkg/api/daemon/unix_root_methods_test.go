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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var unixRootOnlyTestMethods = []string{
	"/platform.v1.CAService/InitCA",
	"/platform.v1.CAService/InstallCACertificates",
	"/platform.v1.CAService/UninstallCACertificates",
}

func countingHandler(calls *int, resp any) grpc.UnaryHandler {
	return func(context.Context, any) (any, error) {
		*calls++
		return resp, nil
	}
}

func TestUnixRootOnly_RefusesANonRootPeer(t *testing.T) {
	interceptor := UnixRootOnlyUnaryInterceptor()
	ctx := peercred.ContextWithUnixCredentials(context.Background(),
		peercred.UnixCredentials{PID: 1, UID: 1000, GID: 1000})
	for _, m := range unixRootOnlyTestMethods {
		t.Run(m, func(t *testing.T) {
			calls := 0
			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: m}, countingHandler(&calls, "ok"))
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "uid 1000")
			assert.Equal(t, 0, calls)
		})
	}
}

func TestUnixRootOnly_AdmitsRoot(t *testing.T) {
	interceptor := UnixRootOnlyUnaryInterceptor()
	ctx := peercred.ContextWithUnixCredentials(context.Background(),
		peercred.UnixCredentials{PID: 1, UID: 0, GID: 0})
	for _, m := range unixRootOnlyTestMethods {
		t.Run(m, func(t *testing.T) {
			calls := 0
			want := &platformv1.InitCAResponse{}
			resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: m}, countingHandler(&calls, want))
			require.NoError(t, err)
			assert.Same(t, want, resp)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestUnixRootOnly_OtherMethodsPass(t *testing.T) {
	interceptor := UnixRootOnlyUnaryInterceptor()
	ctx := peercred.ContextWithUnixCredentials(context.Background(),
		peercred.UnixCredentials{PID: 1, UID: 1000, GID: 1000})
	calls := 0
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/platform.v1.CAService/GetCAInfo"}, countingHandler(&calls, "ok"))
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestUnixRootOnly_NoCredentialsFailsClosed(t *testing.T) {
	interceptor := UnixRootOnlyUnaryInterceptor()
	calls := 0
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/platform.v1.CAService/InitCA"}, countingHandler(&calls, "ok"))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Equal(t, 0, calls)
}

func TestUnixGRPCServerOptions_GuardTheCALifecycle(t *testing.T) {
	// A short directory: sun_path is 108 bytes and t.TempDir() can exceed it.
	dir, err := os.MkdirTemp("", "s2137")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")

	rec := &recordingInitializer{ca: lifecycleCA(t)}
	svc := NewCAGRPCService(nil, nil, nil).WithCAInitializer(rec.init)

	srv := grpc.NewServer(unixGRPCServerOptions(nil)...)
	platformv1.RegisterCAServiceServer(srv, svc)
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(local.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := platformv1.NewCAServiceClient(conn)

	_, err = client.InitCA(context.Background(), &platformv1.InitCARequest{})
	if os.Geteuid() != 0 {
		t.Log("euid is not root: InitCA must be refused")
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		assert.Equal(t, 0, rec.calls)
	} else {
		t.Log("euid is root: InitCA must be admitted")
		require.NoError(t, err)
		assert.Equal(t, 1, rec.calls)
	}

	_, err = client.GetCAInfo(context.Background(), &platformv1.GetCAInfoRequest{})
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}

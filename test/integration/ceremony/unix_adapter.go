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

//go:build integration

package ceremony

import (
	"context"
	"os"

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// UnixAdapter drives ceremony operations over gRPC-over-UDS. It reuses the
// same SDK gRPC client as GRPCAdapter; only the dial target changes.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *ceremonysdk.GRPCClient
}

// NewUnixAdapter returns an unconfigured Unix adapter.
func NewUnixAdapter() *UnixAdapter { return &UnixAdapter{} }

// Name returns "Unix".
func (u *UnixAdapter) Name() string { return "Unix" }

// Setup dials the platformd Unix domain socket. Unix sockets do not use TLS;
// platformd enforces peer credentials via SO_PEERCRED instead.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	socketPath := os.Getenv(EnvPlatformUnixSocket)
	if socketPath == "" {
		socketPath = GetServiceEndpoints().PlatformUnix
	}
	u.socketPath = socketPath

	if _, err := os.Stat(socketPath); err != nil {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: socketPath, Err: err}
	}

	conn, err := grpc.NewClient("unix://"+socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: socketPath, Err: err}
	}
	u.conn = conn
	u.client = ceremonysdk.NewGRPCClient(conn)
	return nil
}

// Teardown closes the Unix-socket gRPC connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// Init proxies Init over Unix.
func (u *UnixAdapter) Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error) {
	return u.client.Init(ctx, req)
}

// Status proxies Status over Unix.
func (u *UnixAdapter) Status(ctx context.Context) (*ceremonysdk.StatusResponse, error) {
	return u.client.Status(ctx)
}

// ClaimCertBegin proxies ClaimCertBegin over Unix.
func (u *UnixAdapter) ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error) {
	return u.client.ClaimCertBegin(ctx, req)
}

// ClaimCertComplete proxies ClaimCertComplete over Unix.
func (u *UnixAdapter) ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error) {
	return u.client.ClaimCertComplete(ctx, req)
}

// ClaimShareBegin proxies ClaimShareBegin over Unix.
func (u *UnixAdapter) ClaimShareBegin(ctx context.Context, req *ceremonysdk.ClaimShareBeginRequest) (*ceremonysdk.ClaimShareBeginResponse, error) {
	return u.client.ClaimShareBegin(ctx, req)
}

// ClaimShareComplete proxies ClaimShareComplete over Unix.
func (u *UnixAdapter) ClaimShareComplete(ctx context.Context, req *ceremonysdk.ClaimShareCompleteRequest) (*ceremonysdk.ClaimShareCompleteResponse, error) {
	return u.client.ClaimShareComplete(ctx, req)
}

// SignCSR proxies SignCSR over Unix.
func (u *UnixAdapter) SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error) {
	return u.client.SignCSR(ctx, req)
}

var _ CeremonyCommands = (*UnixAdapter)(nil)

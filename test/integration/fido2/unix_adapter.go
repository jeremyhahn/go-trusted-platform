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

package fido2

import (
	"context"
	"os"

	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// UnixAdapter drives FIDO2 operations over gRPC-over-UDS.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *fido2sdk.GRPCClient
}

// NewUnixAdapter returns an unconfigured Unix adapter.
func NewUnixAdapter() *UnixAdapter { return &UnixAdapter{} }

// Name returns "Unix".
func (u *UnixAdapter) Name() string { return "Unix" }

// Setup dials platformd over the Unix domain socket.
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
	u.client = fido2sdk.NewGRPCClient(conn)
	return nil
}

// Teardown closes the Unix-socket gRPC connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// ListDevices proxies ListDevices over Unix.
func (u *UnixAdapter) ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error) {
	return u.client.ListDevices(ctx, req)
}

// WaitDevice proxies WaitDevice over Unix.
func (u *UnixAdapter) WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error) {
	return u.client.WaitDevice(ctx, req)
}

// Info proxies Info over Unix.
func (u *UnixAdapter) Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error) {
	return u.client.Info(ctx, req)
}

// Register proxies Register over Unix.
func (u *UnixAdapter) Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error) {
	return u.client.Register(ctx, req)
}

// Authenticate proxies Authenticate over Unix.
func (u *UnixAdapter) Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error) {
	return u.client.Authenticate(ctx, req)
}

var _ FIDO2Commands = (*UnixAdapter)(nil)

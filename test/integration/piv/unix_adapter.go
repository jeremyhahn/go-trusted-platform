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

package piv

import (
	"context"
	"os"

	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// UnixAdapter drives PIV operations over gRPC-over-UDS. It reuses the SDK
// gRPC client — only the dial target changes from TCP to a Unix socket.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *pivsdk.GRPCClient
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
	u.client = pivsdk.NewGRPCClient(conn)
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
func (u *UnixAdapter) ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error) {
	return u.client.ListDevices(ctx, req)
}

// ListSlots proxies ListSlots over Unix.
func (u *UnixAdapter) ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error) {
	return u.client.ListSlots(ctx, req)
}

// SlotInfo proxies SlotInfo over Unix.
func (u *UnixAdapter) SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error) {
	return u.client.SlotInfo(ctx, req)
}

// Generate proxies Generate over Unix.
func (u *UnixAdapter) Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error) {
	return u.client.Generate(ctx, req)
}

// Import proxies Import over Unix.
func (u *UnixAdapter) Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error) {
	return u.client.Import(ctx, req)
}

// Sign proxies Sign over Unix.
func (u *UnixAdapter) Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error) {
	return u.client.Sign(ctx, req)
}

// Attest proxies Attest over Unix.
func (u *UnixAdapter) Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error) {
	return u.client.Attest(ctx, req)
}

// Reset proxies Reset over Unix.
func (u *UnixAdapter) Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error) {
	return u.client.Reset(ctx, req)
}

var _ PIVCommands = (*UnixAdapter)(nil)

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

// GRPCAdapter drives FIDO2 operations over TLS gRPC.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *fido2sdk.GRPCClient
}

// NewGRPCAdapter returns an unconfigured gRPC adapter.
func NewGRPCAdapter() *GRPCAdapter { return &GRPCAdapter{} }

// Name returns "gRPC".
func (g *GRPCAdapter) Name() string { return "gRPC" }

// Setup dials platformd over gRPC.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformGRPC
	}
	g.endpoint = endpoint
	conn, err := grpc.NewClient(endpoint, helpers.GRPCTransportCredentials())
	if err != nil {
		return ErrConnectionFailed{Protocol: "gRPC", Endpoint: endpoint, Err: err}
	}
	g.conn = conn
	g.client = fido2sdk.NewGRPCClient(conn)
	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// ListDevices proxies ListDevices.
func (g *GRPCAdapter) ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error) {
	return g.client.ListDevices(ctx, req)
}

// WaitDevice proxies WaitDevice.
func (g *GRPCAdapter) WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error) {
	return g.client.WaitDevice(ctx, req)
}

// Info proxies Info.
func (g *GRPCAdapter) Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error) {
	return g.client.Info(ctx, req)
}

// Register proxies Register.
func (g *GRPCAdapter) Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error) {
	return g.client.Register(ctx, req)
}

// Authenticate proxies Authenticate.
func (g *GRPCAdapter) Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error) {
	return g.client.Authenticate(ctx, req)
}

var _ FIDO2Commands = (*GRPCAdapter)(nil)

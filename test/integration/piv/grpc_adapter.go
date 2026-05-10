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

// GRPCAdapter drives PIV operations over TLS gRPC.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *pivsdk.GRPCClient
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
	g.client = pivsdk.NewGRPCClient(conn)
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
func (g *GRPCAdapter) ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error) {
	return g.client.ListDevices(ctx, req)
}

// ListSlots proxies ListSlots.
func (g *GRPCAdapter) ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error) {
	return g.client.ListSlots(ctx, req)
}

// SlotInfo proxies SlotInfo.
func (g *GRPCAdapter) SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error) {
	return g.client.SlotInfo(ctx, req)
}

// Generate proxies Generate.
func (g *GRPCAdapter) Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error) {
	return g.client.Generate(ctx, req)
}

// Import proxies Import.
func (g *GRPCAdapter) Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error) {
	return g.client.Import(ctx, req)
}

// Sign proxies Sign.
func (g *GRPCAdapter) Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error) {
	return g.client.Sign(ctx, req)
}

// Attest proxies Attest.
func (g *GRPCAdapter) Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error) {
	return g.client.Attest(ctx, req)
}

// Reset proxies Reset.
func (g *GRPCAdapter) Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error) {
	return g.client.Reset(ctx, req)
}

var _ PIVCommands = (*GRPCAdapter)(nil)

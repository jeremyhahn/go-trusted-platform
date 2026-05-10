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

package luks

import (
	"context"
	"os"

	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// GRPCAdapter drives LUKS operations over TLS gRPC.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *lukssdk.GRPCClient
}

// NewGRPCAdapter returns an unconfigured gRPC adapter.
func NewGRPCAdapter() *GRPCAdapter { return &GRPCAdapter{} }

// Name returns "gRPC".
func (g *GRPCAdapter) Name() string { return "gRPC" }

// Setup dials platformd.
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
	g.client = lukssdk.NewGRPCClient(conn)
	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// Status proxies Status.
func (g *GRPCAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	return g.client.Status(ctx, req)
}

// ListSlots proxies ListSlots.
func (g *GRPCAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	return g.client.ListSlots(ctx, req)
}

// Info proxies Info.
func (g *GRPCAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	return g.client.Info(ctx, req)
}

// EnrollPassphrase proxies EnrollPassphrase.
func (g *GRPCAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	return g.client.EnrollPassphrase(ctx, req)
}

// EnrollFIDO2 proxies EnrollFIDO2.
func (g *GRPCAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	return g.client.EnrollFIDO2(ctx, req)
}

// EnrollTPM proxies EnrollTPM.
func (g *GRPCAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	return g.client.EnrollTPM(ctx, req)
}

// EnrollRecovery proxies EnrollRecovery.
func (g *GRPCAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	return g.client.EnrollRecovery(ctx, req)
}

// RemoveKey proxies RemoveKey.
func (g *GRPCAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	return g.client.RemoveKey(ctx, req)
}

// TestUnlock proxies TestUnlock.
func (g *GRPCAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	return g.client.TestUnlock(ctx, req)
}

// ChangePassphrase proxies ChangePassphrase.
func (g *GRPCAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	return g.client.ChangePassphrase(ctx, req)
}

var _ LUKSCommands = (*GRPCAdapter)(nil)

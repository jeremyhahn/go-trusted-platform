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

// GRPCAdapter drives ceremony operations over a TLS gRPC connection.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *ceremonysdk.GRPCClient
}

// NewGRPCAdapter returns an unconfigured gRPC adapter. Setup dials platformd.
func NewGRPCAdapter() *GRPCAdapter { return &GRPCAdapter{} }

// Name returns "gRPC".
func (g *GRPCAdapter) Name() string { return "gRPC" }

// Setup dials the platformd gRPC endpoint using mTLS credentials from env.
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
	g.client = ceremonysdk.NewGRPCClient(conn)
	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// Init proxies Init to the SDK gRPC client.
func (g *GRPCAdapter) Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error) {
	return g.client.Init(ctx, req)
}

// Status proxies Status to the SDK gRPC client.
func (g *GRPCAdapter) Status(ctx context.Context) (*ceremonysdk.StatusResponse, error) {
	return g.client.Status(ctx)
}

// ClaimCertBegin proxies ClaimCertBegin to the SDK gRPC client.
func (g *GRPCAdapter) ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error) {
	return g.client.ClaimCertBegin(ctx, req)
}

// ClaimCertComplete proxies ClaimCertComplete to the SDK gRPC client.
func (g *GRPCAdapter) ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error) {
	return g.client.ClaimCertComplete(ctx, req)
}

// ClaimShareBegin proxies ClaimShareBegin to the SDK gRPC client.
func (g *GRPCAdapter) ClaimShareBegin(ctx context.Context, req *ceremonysdk.ClaimShareBeginRequest) (*ceremonysdk.ClaimShareBeginResponse, error) {
	return g.client.ClaimShareBegin(ctx, req)
}

// ClaimShareComplete proxies ClaimShareComplete to the SDK gRPC client.
func (g *GRPCAdapter) ClaimShareComplete(ctx context.Context, req *ceremonysdk.ClaimShareCompleteRequest) (*ceremonysdk.ClaimShareCompleteResponse, error) {
	return g.client.ClaimShareComplete(ctx, req)
}

// SignCSR proxies SignCSR to the SDK gRPC client.
func (g *GRPCAdapter) SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error) {
	return g.client.SignCSR(ctx, req)
}

var _ CeremonyCommands = (*GRPCAdapter)(nil)

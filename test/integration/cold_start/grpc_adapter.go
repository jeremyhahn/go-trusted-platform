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

package cold_start

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// GRPCAdapter drives cold-start auth operations over a TLS gRPC
// connection. The auth/factor service is being stood up under #143-b/c;
// until those land the adapter surfaces "not yet wired" for every
// auth-mutating call.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
}

// NewGRPCAdapter returns an unconfigured gRPC adapter.
func NewGRPCAdapter() *GRPCAdapter { return &GRPCAdapter{} }

// Name returns "gRPC".
func (g *GRPCAdapter) Name() string { return "gRPC" }

// Setup dials platformd over TLS using the harness ports.
func (g *GRPCAdapter) Setup(ctx context.Context, h *Harness) error {
	g.endpoint = GetServiceEndpoints(h.Config()).GRPC
	conn, err := grpc.NewClient(g.endpoint, helpers.GRPCTransportCredentials())
	if err != nil {
		return err
	}
	g.conn = conn
	return nil
}

// Teardown closes the connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// Health asks the daemon for its current state via the canonical health
// service. The cold-start scenario's primary view of state is the REST
// /healthz, so we surface the connection state as ready when the
// channel is up.
func (g *GRPCAdapter) Health(ctx context.Context) (*HealthSnapshot, error) {
	if g.conn == nil {
		return nil, &ErrAdapterNotReady{Adapter: "gRPC"}
	}
	return &HealthSnapshot{State: "unsealed", Ready: true}, nil
}

// AddMTLSFactor invokes the auth-factor gRPC service. Stubbed.
func (g *GRPCAdapter) AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error {
	return notWired("gRPC", "auth factor add")
}

// ListFactors lists factors. Stubbed.
func (g *GRPCAdapter) ListFactors(ctx context.Context, username string) ([]FactorRecord, error) {
	return nil, notWired("gRPC", "auth factor list")
}

// LoginMTLS performs an mTLS login. Stubbed.
func (g *GRPCAdapter) LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error) {
	return nil, notWired("gRPC", "auth login")
}

// RotateMTLSFactor rotates a factor. Stubbed.
func (g *GRPCAdapter) RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error) {
	return "", notWired("gRPC", "auth factor rotate")
}

// RemoveFactor removes a factor. Stubbed.
func (g *GRPCAdapter) RemoveFactor(ctx context.Context, username, factorID string) error {
	return notWired("gRPC", "auth factor remove")
}

var _ ColdStartCommands = (*GRPCAdapter)(nil)

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vpn

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkvpn "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so the adapter can select any of
	// them by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// SDKAdapter drives VPNCommands through the platform SDK over one selected
// transport, exercising the exact adapter tables (REST route map, QUIC
// category/sub-opcode map, MCP tool map) the production clients use.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() *platform.Options
	client   platform.Client
	vpn      *sdkvpn.Client
}

// NewGRPCAdapter drives the VPN service over TLS gRPC.
func NewGRPCAdapter() *SDKAdapter {
	endpoint := helpers.GetGRPCEndpoint()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolGRPC),
				platform.WithGRPCAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewRESTAdapter drives the VPN service over HTTPS REST.
func NewRESTAdapter() *SDKAdapter {
	endpoint := helpers.GetRESTEndpoint()
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolREST),
				platform.WithRESTAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewQUICAdapter drives the VPN service over QUIC category 0x52.
func NewQUICAdapter() *SDKAdapter {
	endpoint := helpers.GetQUICEndpoint()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewMCPAdapter drives the VPN service over MCP.
func NewMCPAdapter() *SDKAdapter {
	endpoint := helpers.GetMCPEndpoint()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoint),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewUnixAdapter drives the VPN service over gRPC-over-UDS, the CLI default.
func NewUnixAdapter() *SDKAdapter {
	endpoint := helpers.GetSocketPath()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoint,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoint),
			)
		},
	}
}

// Name returns the transport name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the platform SDK client over the selected transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, a.options())
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.vpn = sdkvpn.NewClientFromGRPC(client.VPN())
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// EnrolPeer implements VPNCommands.
func (a *SDKAdapter) EnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (*platformv1.VPNPeer, error) {
	return a.vpn.EnrolPeer(ctx, tenantID, deviceID, zones)
}

// ListPeers implements VPNCommands.
func (a *SDKAdapter) ListPeers(ctx context.Context, tenantID string) ([]*platformv1.VPNPeer, error) {
	return a.vpn.ListPeers(ctx, tenantID)
}

// RevokePeer implements VPNCommands.
func (a *SDKAdapter) RevokePeer(ctx context.Context, tenantID, deviceID string) error {
	return a.vpn.RevokePeer(ctx, tenantID, deviceID)
}

// Status implements VPNCommands.
func (a *SDKAdapter) Status(ctx context.Context, gatewayID string) ([]*platformv1.VPNGatewayStatus, error) {
	return a.vpn.Status(ctx, gatewayID)
}

// GetPosturePolicy implements VPNCommands.
func (a *SDKAdapter) GetPosturePolicy(ctx context.Context, tenantID, name string) (*platformv1.VPNPosturePolicy, error) {
	return a.vpn.GetPosturePolicy(ctx, tenantID, name)
}

// SetPosturePolicy implements VPNCommands.
func (a *SDKAdapter) SetPosturePolicy(ctx context.Context, tenantID, name, module string) (*platformv1.VPNPosturePolicy, error) {
	return a.vpn.SetPosturePolicy(ctx, tenantID, name, module)
}

// DeletePosturePolicy implements VPNCommands.
func (a *SDKAdapter) DeletePosturePolicy(ctx context.Context, tenantID, name string) error {
	return a.vpn.DeletePosturePolicy(ctx, tenantID, name)
}

// ListPosturePolicies implements VPNCommands.
func (a *SDKAdapter) ListPosturePolicies(ctx context.Context, tenantID string) ([]*platformv1.VPNPosturePolicy, error) {
	return a.vpn.ListPosturePolicies(ctx, tenantID)
}

// Compile-time check: the SDK adapter satisfies the shared surface.
var _ VPNCommands = (*SDKAdapter)(nil)

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

package provision

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	provisionsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register the SDK protocol connectors used by the adapters below.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// SDKAdapter drives the ConfigDeliveryService through the platform SDK
// (sdk/go) pinned to a single protocol via WithOnlyProtocol. One adapter
// type covers REST, gRPC, QUIC, MCP, and Unix because the SDK provision
// client (sdk/go/services/provision) is transport-agnostic — exactly the
// path platformctl uses in production.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() ([]platform.Option, error)
	client   platform.Client
	prov     *provisionsdk.Client
}

// Name returns the protocol name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the SDK client on the adapter's protocol and wraps its
// ConfigDelivery client in the provisioning service client.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	opts, err := a.options()
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	client, err := platform.NewClient(ctx, opts...)
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.prov = provisionsdk.NewClientFromGRPC(client.ConfigDelivery())
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// GetNonce proxies GetNonce to the SDK provision client.
func (a *SDKAdapter) GetNonce(ctx context.Context) (string, error) {
	return a.prov.GetNonce(ctx)
}

// FetchConfig proxies FetchConfig to the SDK provision client.
func (a *SDKAdapter) FetchConfig(ctx context.Context, req *platformv1.FetchConfigRequest) (*platformv1.FetchConfigResponse, error) {
	return a.prov.FetchConfig(ctx, req)
}

// SignDigest proxies SignDigest to the SDK provision client.
func (a *SDKAdapter) SignDigest(ctx context.Context, req *platformv1.SignDigestRequest) (*platformv1.SignDigestResponse, error) {
	return a.prov.SignDigest(ctx, req)
}

// ListSessions proxies ListSessions to the SDK provision client.
func (a *SDKAdapter) ListSessions(ctx context.Context) ([]*platformv1.ProvisioningSession, error) {
	return a.prov.ListSessions(ctx)
}

// GetSession proxies GetSession to the SDK provision client.
func (a *SDKAdapter) GetSession(ctx context.Context, sessionID string) (*platformv1.ProvisioningSession, error) {
	return a.prov.GetSession(ctx, sessionID)
}

// FulfillSession proxies FulfillSession to the SDK provision client.
func (a *SDKAdapter) FulfillSession(ctx context.Context, sessionID string, profileID uint64) (*platformv1.FulfillSessionResponse, error) {
	return a.prov.FulfillSession(ctx, sessionID, profileID)
}

// PollSession proxies PollSession to the SDK provision client.
func (a *SDKAdapter) PollSession(ctx context.Context, sessionID string) (*platformv1.PollSessionResponse, error) {
	return a.prov.PollSession(ctx, sessionID)
}

// mtlsOptions builds the shared mTLS option set for TLS transports.
func mtlsOptions(protocol string, extra ...platform.Option) func() ([]platform.Option, error) {
	return func() ([]platform.Option, error) {
		tlsConfig := helpers.LoadMTLSConfig()
		if tlsConfig == nil {
			return nil, ErrMTLSNotConfigured{Protocol: protocol}
		}
		return append([]platform.Option{platform.WithTLSConfig(tlsConfig)}, extra...), nil
	}
}

// NewGRPCAdapter returns an adapter pinned to the gRPC TCP transport.
func NewGRPCAdapter() *SDKAdapter {
	endpoint := grpcEndpoint()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoint,
		options: mtlsOptions("gRPC",
			platform.WithOnlyProtocol(platform.ProtocolGRPC),
			platform.WithGRPCAddr(endpoint),
		),
	}
}

// NewRESTAdapter returns an adapter pinned to the REST transport.
func NewRESTAdapter() *SDKAdapter {
	endpoint := restEndpoint()
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoint,
		options: mtlsOptions("REST",
			platform.WithOnlyProtocol(platform.ProtocolREST),
			platform.WithRESTAddr(endpoint),
		),
	}
}

// NewQUICAdapter returns an adapter pinned to the QUIC transport.
func NewQUICAdapter() *SDKAdapter {
	endpoint := quicEndpoint()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoint,
		options: mtlsOptions("QUIC",
			platform.WithOnlyProtocol(platform.ProtocolQUIC),
			platform.WithQUICAddr(endpoint),
		),
	}
}

// NewMCPAdapter returns an adapter pinned to the MCP transport. The MCP
// server serves plain HTTP on its dedicated port, so no TLS config is set.
func NewMCPAdapter() *SDKAdapter {
	endpoint := mcpEndpoint()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoint,
		options: func() ([]platform.Option, error) {
			return []platform.Option{
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoint),
			}, nil
		},
	}
}

// NewUnixAdapter returns an adapter pinned to the Unix socket transport
// (gRPC over UDS, no TLS — the socket relies on kernel permissions).
func NewUnixAdapter() *SDKAdapter {
	endpoint := unixSocket()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoint,
		options: func() ([]platform.Option, error) {
			return []platform.Option{
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoint),
			}, nil
		},
	}
}

// Compile-time interface checks.
var _ ProvisionCommands = (*SDKAdapter)(nil)

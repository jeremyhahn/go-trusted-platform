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

package proxy

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkproxy "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/proxy"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so the adapter can select any of
	// them by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// SDKAdapter drives ProxyCommands through the platform SDK over one
// selected transport, exercising the exact code path the gatewayd sync
// loop uses.
type SDKAdapter struct {
	name     string
	options  func() (*platform.Options, error)
	endpoint string
	client   platform.Client
	proxy    *sdkproxy.Client
}

// NewGRPCAdapter drives the proxy service over TLS gRPC.
func NewGRPCAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoints.PlatformGRPC,
		options: func() (*platform.Options, error) {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolGRPC),
				platform.WithGRPCAddr(endpoints.PlatformGRPC),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			), nil
		},
	}
}

// NewRESTAdapter drives the proxy service over the REST transport.
func NewRESTAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoints.PlatformREST,
		options: func() (*platform.Options, error) {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolREST),
				platform.WithRESTAddr(endpoints.PlatformREST),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			), nil
		},
	}
}

// NewQUICAdapter drives the proxy service over the QUIC transport.
func NewQUICAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoints.PlatformQUIC,
		options: func() (*platform.Options, error) {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoints.PlatformQUIC),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			), nil
		},
	}
}

// NewMCPAdapter drives the proxy service over the MCP transport.
func NewMCPAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoints.PlatformMCP,
		options: func() (*platform.Options, error) {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoints.PlatformMCP),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			), nil
		},
	}
}

// NewUnixAdapter drives the proxy service over gRPC-over-UDS — the default
// gatewayd control-plane path.
func NewUnixAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoints.PlatformUnix,
		options: func() (*platform.Options, error) {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoints.PlatformUnix),
			), nil
		},
	}
}

// Name returns the transport name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the platform SDK client over the selected transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	opts, err := a.options()
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	client, err := platform.Connect(ctx, opts)
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.proxy = sdkproxy.NewClientFromGRPC(client.Proxy())
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// CreateRoute implements ProxyCommands.
func (a *SDKAdapter) CreateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	return a.proxy.CreateRoute(ctx, route)
}

// GetRoute implements ProxyCommands.
func (a *SDKAdapter) GetRoute(ctx context.Context, id string) (*platformv1.ProxyRoute, error) {
	return a.proxy.GetRoute(ctx, id)
}

// UpdateRoute implements ProxyCommands.
func (a *SDKAdapter) UpdateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	return a.proxy.UpdateRoute(ctx, route)
}

// DeleteRoute implements ProxyCommands.
func (a *SDKAdapter) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	return a.proxy.DeleteRoute(ctx, id)
}

// ListRoutes implements ProxyCommands.
func (a *SDKAdapter) ListRoutes(ctx context.Context) ([]*platformv1.ProxyRoute, uint64, error) {
	return a.proxy.ListRoutes(ctx)
}

// CreatePool implements ProxyCommands.
func (a *SDKAdapter) CreatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	return a.proxy.CreatePool(ctx, pool)
}

// GetPool implements ProxyCommands.
func (a *SDKAdapter) GetPool(ctx context.Context, id string) (*platformv1.ProxyPool, error) {
	return a.proxy.GetPool(ctx, id)
}

// UpdatePool implements ProxyCommands.
func (a *SDKAdapter) UpdatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	return a.proxy.UpdatePool(ctx, pool)
}

// DeletePool implements ProxyCommands.
func (a *SDKAdapter) DeletePool(ctx context.Context, id string) (uint64, error) {
	return a.proxy.DeletePool(ctx, id)
}

// ListPools implements ProxyCommands.
func (a *SDKAdapter) ListPools(ctx context.Context) ([]*platformv1.ProxyPool, uint64, error) {
	return a.proxy.ListPools(ctx)
}

// Status implements ProxyCommands.
func (a *SDKAdapter) Status(ctx context.Context) (*platformv1.GetProxyStatusResponse, error) {
	return a.proxy.Status(ctx)
}

// Reload implements ProxyCommands.
func (a *SDKAdapter) Reload(ctx context.Context) (uint64, error) {
	return a.proxy.Reload(ctx)
}

// ZoneMatrix implements ProxyCommands.
func (a *SDKAdapter) ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error) {
	return a.proxy.ZoneMatrix(ctx)
}

var _ ProxyCommands = (*SDKAdapter)(nil)

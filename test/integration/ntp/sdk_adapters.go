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

package ntp

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkntp "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ntp"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so the adapter can select any of
	// them by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// SDKAdapter drives NTPCommands through the platform SDK over one selected
// transport, exercising the exact adapter tables (REST route map, QUIC
// category/sub-opcode map, MCP tool map) the production clients use.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() *platform.Options
	// bearer, when set, supplies the bearer the transport presents: the
	// REST adapter reaches the admin-gated webservice routes with the
	// harness admin session's bearer.
	bearer func(ctx context.Context) (string, error)
	client platform.Client
	ntp    *sdkntp.Client
}

// NewGRPCAdapter drives the NTP service over TLS gRPC.
func NewGRPCAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoints.PlatformGRPC,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolGRPC),
				platform.WithGRPCAddr(endpoints.PlatformGRPC),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewRESTAdapter drives the NTP service over HTTPS REST.
func NewRESTAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoints.PlatformREST,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolREST),
				platform.WithRESTAddr(endpoints.PlatformREST),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
		bearer: helpers.HarnessAdminSession().Bearer,
	}
}

// NewQUICAdapter drives the NTP service over QUIC.
func NewQUICAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoints.PlatformQUIC,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoints.PlatformQUIC),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewMCPAdapter drives the NTP service over MCP.
func NewMCPAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoints.PlatformMCP,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoints.PlatformMCP),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewUnixAdapter drives the NTP service over gRPC-over-UDS, the CLI default.
func NewUnixAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoints.PlatformUnix,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoints.PlatformUnix),
			)
		},
	}
}

// Name returns the transport name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the platform SDK client over the selected transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	options := a.options()
	if a.bearer != nil {
		token, err := a.bearer(ctx)
		if err != nil {
			return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
		}
		options.BearerToken = token
	}
	client, err := platform.Connect(ctx, options)
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.ntp = sdkntp.NewClientFromGRPC(client.NTP())
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// Status implements NTPCommands.
func (a *SDKAdapter) Status(ctx context.Context) (*platformv1.NTPStatus, error) {
	return a.ntp.Status(ctx)
}

// Sources implements NTPCommands.
func (a *SDKAdapter) Sources(ctx context.Context) ([]*platformv1.NTPSource, error) {
	return a.ntp.Sources(ctx)
}

// Step implements NTPCommands.
func (a *SDKAdapter) Step(ctx context.Context) (*platformv1.NTPStatus, error) {
	return a.ntp.Step(ctx)
}

// Compile-time check: the SDK adapter satisfies the shared surface.
var _ NTPCommands = (*SDKAdapter)(nil)

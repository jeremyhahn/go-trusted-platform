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

package daemon

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// MCP ProxyProvider implementation.
//
// The provider bridges the mcp.ProxyProvider interface onto the daemon's
// shared ProxyGRPCService so the proxy_* MCP tools execute the exact same
// code path (validation, store, error mapping) as the gRPC, REST and QUIC
// transports. Argument maps carry the protobuf-JSON shape of the
// platform.v1 request messages and are decoded via protojson; results are
// the protobuf response messages, which the MCP tool executor normalizes
// through its canonical JSON round-trip.

// Compile-time check: the daemon service provider implements the MCP proxy
// surface.
var _ mcp.ProxyProvider = (*MCPServiceProvider)(nil)

// ErrMCPProxyNotConfigured indicates the proxy service is not wired into
// the MCP provider.
type ErrMCPProxyNotConfigured struct{}

// Error returns the error message.
func (ErrMCPProxyNotConfigured) Error() string {
	return "proxy service not configured (daemon started without proxy store)"
}

// ErrMCPProxyInvalidArgs wraps an argument-map decode failure.
type ErrMCPProxyInvalidArgs struct {
	Cause error
}

// Error returns the error message.
func (e ErrMCPProxyInvalidArgs) Error() string {
	return "invalid proxy tool arguments: " + e.Cause.Error()
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e ErrMCPProxyInvalidArgs) Unwrap() error {
	return e.Cause
}

// proxyArgsToProto decodes an MCP argument map into a platform.v1 request
// message via protojson (accepting both snake_case and camelCase names).
func proxyArgsToProto(args map[string]interface{}, msg proto.Message) error {
	data, err := json.Marshal(args)
	if err != nil {
		return ErrMCPProxyInvalidArgs{Cause: err}
	}
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(data, msg); err != nil {
		return ErrMCPProxyInvalidArgs{Cause: err}
	}
	return nil
}

// requireProxyService guards the proxy provider methods against a nil
// backing service.
func (p *MCPServiceProvider) requireProxyService() error {
	if p.proxyService == nil {
		return ErrMCPProxyNotConfigured{}
	}
	return nil
}

// ProxyRouteCreate creates a route from a CreateProxyRouteRequest argument map.
func (p *MCPServiceProvider) ProxyRouteCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	var req platformv1.CreateProxyRouteRequest
	if err := proxyArgsToProto(args, &req); err != nil {
		return nil, err
	}
	return p.proxyService.CreateRoute(ctx, &req)
}

// ProxyRouteGet retrieves a route by ID.
func (p *MCPServiceProvider) ProxyRouteGet(ctx context.Context, id string) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.GetRoute(ctx, &platformv1.GetProxyRouteRequest{Id: id})
}

// ProxyRouteUpdate replaces a route from an UpdateProxyRouteRequest argument map.
func (p *MCPServiceProvider) ProxyRouteUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	var req platformv1.UpdateProxyRouteRequest
	if err := proxyArgsToProto(args, &req); err != nil {
		return nil, err
	}
	return p.proxyService.UpdateRoute(ctx, &req)
}

// ProxyRouteDelete removes a route by ID.
func (p *MCPServiceProvider) ProxyRouteDelete(ctx context.Context, id string) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.DeleteRoute(ctx, &platformv1.DeleteProxyRouteRequest{Id: id})
}

// ProxyRouteList lists all routes.
func (p *MCPServiceProvider) ProxyRouteList(ctx context.Context) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.ListRoutes(ctx, &platformv1.ListProxyRoutesRequest{})
}

// ProxyPoolCreate creates a backend pool from a CreateProxyPoolRequest
// argument map.
func (p *MCPServiceProvider) ProxyPoolCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	var req platformv1.CreateProxyPoolRequest
	if err := proxyArgsToProto(args, &req); err != nil {
		return nil, err
	}
	return p.proxyService.CreatePool(ctx, &req)
}

// ProxyPoolGet retrieves a backend pool by ID.
func (p *MCPServiceProvider) ProxyPoolGet(ctx context.Context, id string) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.GetPool(ctx, &platformv1.GetProxyPoolRequest{Id: id})
}

// ProxyPoolUpdate replaces a backend pool from an UpdateProxyPoolRequest
// argument map.
func (p *MCPServiceProvider) ProxyPoolUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	var req platformv1.UpdateProxyPoolRequest
	if err := proxyArgsToProto(args, &req); err != nil {
		return nil, err
	}
	return p.proxyService.UpdatePool(ctx, &req)
}

// ProxyPoolDelete removes a backend pool by ID.
func (p *MCPServiceProvider) ProxyPoolDelete(ctx context.Context, id string) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.DeletePool(ctx, &platformv1.DeleteProxyPoolRequest{Id: id})
}

// ProxyPoolList lists all backend pools.
func (p *MCPServiceProvider) ProxyPoolList(ctx context.Context) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.ListPools(ctx, &platformv1.ListProxyPoolsRequest{})
}

// ProxyConfig returns the full merged configuration plus version.
func (p *MCPServiceProvider) ProxyConfig(ctx context.Context) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.GetProxyConfig(ctx, &platformv1.GetProxyConfigRequest{})
}

// ProxyStatus reports the configuration store status.
func (p *MCPServiceProvider) ProxyStatus(ctx context.Context) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.GetProxyStatus(ctx, &platformv1.GetProxyStatusRequest{})
}

// ProxyConfigReload bumps the config version.
func (p *MCPServiceProvider) ProxyConfigReload(ctx context.Context) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.ReloadProxyConfig(ctx, &platformv1.ReloadProxyConfigRequest{})
}

// ProxyZoneMatrix returns the SDN zone matrix.
func (p *MCPServiceProvider) ProxyZoneMatrix(ctx context.Context) (interface{}, error) {
	if err := p.requireProxyService(); err != nil {
		return nil, err
	}
	return p.proxyService.GetZoneMatrix(ctx, &platformv1.GetProxyZoneMatrixRequest{})
}

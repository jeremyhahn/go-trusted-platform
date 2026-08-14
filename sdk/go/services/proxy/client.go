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

// Package proxy provides a client for reverse-proxy configuration
// operations. The client speaks the platform.v1 ProxyService surface over
// any transport.Adapter (gRPC, Unix, REST, QUIC, MCP, embedded), which is
// how gatewayd instances sync the platformd-side route/pool source of
// truth.
package proxy

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to proxy configuration service operations.
type Client struct {
	grpc platformv1.ProxyServiceClient
}

// NewClient creates a new proxy service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewProxyServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new proxy service client from a gRPC client.
// This is useful when you already have a gRPC client from the
// platform.Client.
func NewClientFromGRPC(grpcClient platformv1.ProxyServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Route operations

// CreateRoute creates a new proxy route and returns the stored route plus
// the new config version.
func (c *Client) CreateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	resp, err := c.grpc.CreateRoute(ctx, &platformv1.CreateProxyRouteRequest{Route: route})
	if err != nil {
		return nil, 0, &ErrCreateRouteFailed{ID: route.GetId(), Cause: err}
	}
	return resp.GetRoute(), resp.GetVersion(), nil
}

// GetRoute retrieves a proxy route by ID.
func (c *Client) GetRoute(ctx context.Context, id string) (*platformv1.ProxyRoute, error) {
	resp, err := c.grpc.GetRoute(ctx, &platformv1.GetProxyRouteRequest{Id: id})
	if err != nil {
		return nil, &ErrGetRouteFailed{ID: id, Cause: err}
	}
	return resp.GetRoute(), nil
}

// UpdateRoute replaces an existing proxy route and returns the stored
// route plus the new config version.
func (c *Client) UpdateRoute(ctx context.Context, route *platformv1.ProxyRoute) (*platformv1.ProxyRoute, uint64, error) {
	resp, err := c.grpc.UpdateRoute(ctx, &platformv1.UpdateProxyRouteRequest{
		Id:    route.GetId(),
		Route: route,
	})
	if err != nil {
		return nil, 0, &ErrUpdateRouteFailed{ID: route.GetId(), Cause: err}
	}
	return resp.GetRoute(), resp.GetVersion(), nil
}

// DeleteRoute removes a proxy route by ID and returns the new config
// version.
func (c *Client) DeleteRoute(ctx context.Context, id string) (uint64, error) {
	resp, err := c.grpc.DeleteRoute(ctx, &platformv1.DeleteProxyRouteRequest{Id: id})
	if err != nil {
		return 0, &ErrDeleteRouteFailed{ID: id, Cause: err}
	}
	return resp.GetVersion(), nil
}

// ListRoutes returns all proxy routes plus the current config version.
func (c *Client) ListRoutes(ctx context.Context) ([]*platformv1.ProxyRoute, uint64, error) {
	resp, err := c.grpc.ListRoutes(ctx, &platformv1.ListProxyRoutesRequest{})
	if err != nil {
		return nil, 0, &ErrListRoutesFailed{Cause: err}
	}
	return resp.GetRoutes(), resp.GetVersion(), nil
}

// Pool operations

// CreatePool creates a new backend pool and returns the stored pool plus
// the new config version.
func (c *Client) CreatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	resp, err := c.grpc.CreatePool(ctx, &platformv1.CreateProxyPoolRequest{Pool: pool})
	if err != nil {
		return nil, 0, &ErrCreatePoolFailed{ID: pool.GetId(), Cause: err}
	}
	return resp.GetPool(), resp.GetVersion(), nil
}

// GetPool retrieves a backend pool by ID.
func (c *Client) GetPool(ctx context.Context, id string) (*platformv1.ProxyPool, error) {
	resp, err := c.grpc.GetPool(ctx, &platformv1.GetProxyPoolRequest{Id: id})
	if err != nil {
		return nil, &ErrGetPoolFailed{ID: id, Cause: err}
	}
	return resp.GetPool(), nil
}

// UpdatePool replaces an existing backend pool and returns the stored pool
// plus the new config version.
func (c *Client) UpdatePool(ctx context.Context, pool *platformv1.ProxyPool) (*platformv1.ProxyPool, uint64, error) {
	resp, err := c.grpc.UpdatePool(ctx, &platformv1.UpdateProxyPoolRequest{
		Id:   pool.GetId(),
		Pool: pool,
	})
	if err != nil {
		return nil, 0, &ErrUpdatePoolFailed{ID: pool.GetId(), Cause: err}
	}
	return resp.GetPool(), resp.GetVersion(), nil
}

// DeletePool removes a backend pool by ID and returns the new config
// version.
func (c *Client) DeletePool(ctx context.Context, id string) (uint64, error) {
	resp, err := c.grpc.DeletePool(ctx, &platformv1.DeleteProxyPoolRequest{Id: id})
	if err != nil {
		return 0, &ErrDeletePoolFailed{ID: id, Cause: err}
	}
	return resp.GetVersion(), nil
}

// ListPools returns all backend pools plus the current config version.
func (c *Client) ListPools(ctx context.Context) ([]*platformv1.ProxyPool, uint64, error) {
	resp, err := c.grpc.ListPools(ctx, &platformv1.ListProxyPoolsRequest{})
	if err != nil {
		return nil, 0, &ErrListPoolsFailed{Cause: err}
	}
	return resp.GetPools(), resp.GetVersion(), nil
}

// Config / status / reload / zone matrix operations

// Config returns the full merged proxy configuration plus the version
// counter.
func (c *Client) Config(ctx context.Context) (*platformv1.GetProxyConfigResponse, error) {
	resp, err := c.grpc.GetProxyConfig(ctx, &platformv1.GetProxyConfigRequest{})
	if err != nil {
		return nil, &ErrGetConfigFailed{Cause: err}
	}
	return resp, nil
}

// Status reports the configuration store status.
func (c *Client) Status(ctx context.Context) (*platformv1.GetProxyStatusResponse, error) {
	resp, err := c.grpc.GetProxyStatus(ctx, &platformv1.GetProxyStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return resp, nil
}

// Reload bumps the config version and returns it.
func (c *Client) Reload(ctx context.Context) (uint64, error) {
	resp, err := c.grpc.ReloadProxyConfig(ctx, &platformv1.ReloadProxyConfigRequest{})
	if err != nil {
		return 0, &ErrReloadFailed{Cause: err}
	}
	return resp.GetVersion(), nil
}

// ZoneMatrix returns the SDN zone names and compiled allowed traffic
// pairs.
func (c *Client) ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error) {
	resp, err := c.grpc.GetZoneMatrix(ctx, &platformv1.GetProxyZoneMatrixRequest{})
	if err != nil {
		return nil, &ErrZoneMatrixFailed{Cause: err}
	}
	return resp, nil
}

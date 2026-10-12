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

package mcp

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Proxy (reverse-proxy configuration) tool wiring
// =============================================================================
//
// These tools mirror the platform.v1 ProxyService gRPC surface so AI/LLM
// clients can manage reverse-proxy routes and backend pools over MCP. Tool
// names follow the `proxy_<resource>_<verb>` convention and are routed
// through a map-based dispatcher (O(1) lookup per project conventions).
//
// The MCP server stays decoupled from the daemon: the underlying proxy
// configuration service is exposed via the optional ProxyProvider
// interface, satisfied by the daemon's MCPServiceProvider, which delegates
// to the same shared ProxyGRPCService as the gRPC, REST and QUIC
// transports. Tool arguments and results use the protobuf JSON shapes
// (snake_case field names) so the SDK MCP transport round-trips the
// platform.v1 messages losslessly.

// ErrProxyNotConfigured indicates the proxy configuration backend is not
// wired into the MCP tool registry.
var ErrProxyNotConfigured = errors.New("proxy: configuration service not configured")

// ErrProxyIDRequired indicates the id argument is missing or empty.
var ErrProxyIDRequired = errors.New("proxy: id is required")

// ErrProxyRouteRequired indicates the route argument is missing.
var ErrProxyRouteRequired = errors.New("proxy: route is required")

// ErrProxyPoolRequired indicates the pool argument is missing.
var ErrProxyPoolRequired = errors.New("proxy: pool is required")

// ProxyProvider is the optional interface a ServiceProvider can satisfy to
// unlock the proxy_* MCP tools. Implementations delegate to the shared
// platform ProxyGRPCService (the same backend that powers the gRPC, REST
// and QUIC surfaces) so all transports remain in lockstep.
//
// The map arguments carry the protobuf-JSON shape of the corresponding
// platform.v1 request message (e.g. {"route": {...}} for route create);
// results are the protobuf response messages.
type ProxyProvider interface {
	// ProxyRouteCreate creates a route from a CreateProxyRouteRequest
	// argument map.
	ProxyRouteCreate(ctx context.Context, args map[string]interface{}) (interface{}, error)

	// ProxyRouteGet retrieves a route by ID.
	ProxyRouteGet(ctx context.Context, id string) (interface{}, error)

	// ProxyRouteUpdate replaces a route from an UpdateProxyRouteRequest
	// argument map.
	ProxyRouteUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error)

	// ProxyRouteDelete removes a route by ID.
	ProxyRouteDelete(ctx context.Context, id string) (interface{}, error)

	// ProxyRouteList lists all routes.
	ProxyRouteList(ctx context.Context) (interface{}, error)

	// ProxyPoolCreate creates a backend pool from a CreateProxyPoolRequest
	// argument map.
	ProxyPoolCreate(ctx context.Context, args map[string]interface{}) (interface{}, error)

	// ProxyPoolGet retrieves a backend pool by ID.
	ProxyPoolGet(ctx context.Context, id string) (interface{}, error)

	// ProxyPoolUpdate replaces a backend pool from an UpdateProxyPoolRequest
	// argument map.
	ProxyPoolUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error)

	// ProxyPoolDelete removes a backend pool by ID.
	ProxyPoolDelete(ctx context.Context, id string) (interface{}, error)

	// ProxyPoolList lists all backend pools.
	ProxyPoolList(ctx context.Context) (interface{}, error)

	// ProxyConfig returns the full merged configuration plus version.
	ProxyConfig(ctx context.Context) (interface{}, error)

	// ProxyStatus reports the configuration store status.
	ProxyStatus(ctx context.Context) (interface{}, error)

	// ProxyConfigReload bumps the config version.
	ProxyConfigReload(ctx context.Context) (interface{}, error)

	// ProxyZoneMatrix returns the SDN zone matrix.
	ProxyZoneMatrix(ctx context.Context) (interface{}, error)
}

// proxyProvider returns the ProxyProvider interface if the ServiceProvider
// implements it, else nil.
func (r *ToolRegistry) proxyProvider() ProxyProvider {
	if p, ok := r.service.(ProxyProvider); ok {
		return p
	}
	return nil
}

// registerProxyTools registers the proxy_* MCP tools. Each tool definition
// mirrors the equivalent ProxyService gRPC RPC.
func (r *ToolRegistry) registerProxyTools() {
	idSchema := func(desc string) map[string]interface{} {
		return map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": desc,
				},
			},
			"required": []string{"id"},
		}
	}
	emptySchema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
	routeSchema := map[string]interface{}{
		"type":        "object",
		"description": "Proxy route definition (platform.v1.ProxyRoute JSON): id, hosts, path_prefix, pool_id, auth {mode, require_idevid, allowed_zones, backend_zone, require_attestation, attestation_max_age_nanos, required_roles, required_scopes, opa_policy}, strip_prefix, preserve_host, passthrough_tcp",
	}
	poolSchema := map[string]interface{}{
		"type":        "object",
		"description": "Backend pool definition (platform.v1.ProxyPool JSON): id, backends [{url, weight}], balancer, tls {trust_class, mtls_client_cert}, max_idle_conns_per_host, idle_conn_timeout_nanos",
	}

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_route_create",
		Description: "Create a reverse-proxy route mapping inbound host/path pairs to a backend pool with per-route authentication requirements",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"route": routeSchema,
			},
			"required": []string{"route"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_route_get",
		Description: "Get a reverse-proxy route by ID",
		InputSchema: idSchema("Route identifier"),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_route_update",
		Description: "Replace an existing reverse-proxy route",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Route identifier (may be omitted when route.id is set)",
				},
				"route": routeSchema,
			},
			"required": []string{"route"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_route_delete",
		Description: "Delete a reverse-proxy route by ID",
		InputSchema: idSchema("Route identifier"),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_route_list",
		Description: "List all reverse-proxy routes with the current config version",
		InputSchema: emptySchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_pool_create",
		Description: "Create a reverse-proxy backend pool (set of backends sharing one pooled transport)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pool": poolSchema,
			},
			"required": []string{"pool"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_pool_get",
		Description: "Get a reverse-proxy backend pool by ID",
		InputSchema: idSchema("Pool identifier"),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_pool_update",
		Description: "Replace an existing reverse-proxy backend pool",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Pool identifier (may be omitted when pool.id is set)",
				},
				"pool": poolSchema,
			},
			"required": []string{"pool"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_pool_delete",
		Description: "Delete a reverse-proxy backend pool by ID (denied while routes reference it)",
		InputSchema: idSchema("Pool identifier"),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_pool_list",
		Description: "List all reverse-proxy backend pools with the current config version",
		InputSchema: emptySchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_config",
		Description: "Get the full merged reverse-proxy configuration (routes + pools) with the config version counter",
		InputSchema: emptySchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_status",
		Description: "Get the reverse-proxy configuration store status (version, route/pool counts, last update time)",
		InputSchema: emptySchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_config_reload",
		Description: "Bump the reverse-proxy config version so syncing gatewayd instances re-fetch the configuration",
		InputSchema: emptySchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "proxy_zone_matrix",
		Description: "Get the SDN zone names and compiled allowed (from, to) traffic pairs",
		InputSchema: emptySchema,
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// proxyToolHandler dispatches a proxy tool by name. Map-based dispatch
// keeps routing O(1) per project conventions.
type proxyToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var proxyToolDispatch = map[string]proxyToolHandler{
	"proxy_route_create":  (*ToolRegistry).executeProxyRouteCreate,
	"proxy_route_get":     (*ToolRegistry).executeProxyRouteGet,
	"proxy_route_update":  (*ToolRegistry).executeProxyRouteUpdate,
	"proxy_route_delete":  (*ToolRegistry).executeProxyRouteDelete,
	"proxy_route_list":    (*ToolRegistry).executeProxyRouteList,
	"proxy_pool_create":   (*ToolRegistry).executeProxyPoolCreate,
	"proxy_pool_get":      (*ToolRegistry).executeProxyPoolGet,
	"proxy_pool_update":   (*ToolRegistry).executeProxyPoolUpdate,
	"proxy_pool_delete":   (*ToolRegistry).executeProxyPoolDelete,
	"proxy_pool_list":     (*ToolRegistry).executeProxyPoolList,
	"proxy_config":        (*ToolRegistry).executeProxyConfig,
	"proxy_status":        (*ToolRegistry).executeProxyStatus,
	"proxy_config_reload": (*ToolRegistry).executeProxyConfigReload,
	"proxy_zone_matrix":   (*ToolRegistry).executeProxyZoneMatrix,
}

// dispatchProxyTool looks up a proxy tool and invokes it. Returns
// (result, handled, err) so the caller can fall through when handled is
// false (tool name doesn't belong to the proxy surface).
func (r *ToolRegistry) dispatchProxyTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := proxyToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// proxyResourceID extracts the required id argument.
func proxyResourceID(args map[string]interface{}) (string, error) {
	id := getString(args, "id")
	if id == "" {
		return "", ErrProxyIDRequired
	}
	return id, nil
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeProxyRouteCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	if _, ok := args["route"]; !ok {
		return nil, ErrProxyRouteRequired
	}
	result, err := p.ProxyRouteCreate(ctx, args)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyRouteGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	id, err := proxyResourceID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProxyRouteGet(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyRouteUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	if _, ok := args["route"]; !ok {
		return nil, ErrProxyRouteRequired
	}
	result, err := p.ProxyRouteUpdate(ctx, args)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyRouteDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	id, err := proxyResourceID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProxyRouteDelete(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyRouteList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	result, err := p.ProxyRouteList(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyPoolCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	if _, ok := args["pool"]; !ok {
		return nil, ErrProxyPoolRequired
	}
	result, err := p.ProxyPoolCreate(ctx, args)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyPoolGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	id, err := proxyResourceID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProxyPoolGet(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyPoolUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	if _, ok := args["pool"]; !ok {
		return nil, ErrProxyPoolRequired
	}
	result, err := p.ProxyPoolUpdate(ctx, args)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyPoolDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	id, err := proxyResourceID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProxyPoolDelete(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyPoolList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	result, err := p.ProxyPoolList(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyConfig(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	result, err := p.ProxyConfig(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	result, err := p.ProxyStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyConfigReload(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	result, err := p.ProxyConfigReload(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProxyZoneMatrix(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.proxyProvider()
	if p == nil {
		return nil, ErrProxyNotConfigured
	}
	result, err := p.ProxyZoneMatrix(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

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
// Cluster tool wiring
// =============================================================================
//
// These tools mirror the gRPC ClusterService surface so AI/LLM clients can
// drive the same cluster lifecycle workflows over MCP. Tool names follow
// the project convention `platform_cluster_<verb>` and are routed through
// a map-based dispatcher (O(1) lookup per project conventions).
//
// The MCP server stays decoupled from the daemon: the underlying daemon
// service is exposed via the optional ClusterProvider interface, satisfied
// by the daemon's MCPServiceProvider when a cluster service is wired in.
// When a provider is not wired, every cluster tool returns
// ErrClusterNotConfigured so clients get a clear, structured failure
// rather than a generic "unknown tool" error.

// ErrClusterNotConfigured indicates the cluster backend is not wired into
// the MCP tool registry. Clients see this when the daemon was started
// without cluster support (e.g., built without -tags cluster, or
// QuicBaaS does not expose a coordinator).
var ErrClusterNotConfigured = errors.New("cluster: service provider not configured")

// ErrClusterSeedAddressRequired indicates the `seed_addresses` argument
// was missing or empty for a join operation.
var ErrClusterSeedAddressRequired = errors.New("cluster: seed_addresses is required and must contain at least one address")

// ClusterProvider is the optional interface a ServiceProvider can satisfy
// to unlock cluster MCP tools. Implementations are expected to delegate to
// the platform's ClusterServicer (the same backing service that powers
// the gRPC ClusterService) so the MCP and gRPC surfaces remain in
// lockstep.
//
// Method names map to MCP tools: platform_cluster_bootstrap, etc.
type ClusterProvider interface {
	// Lifecycle
	ClusterBootstrap(ctx context.Context, clusterName string) (interface{}, error)
	ClusterJoin(ctx context.Context, seedAddresses []string) (interface{}, error)
	ClusterLeave(ctx context.Context) (interface{}, error)

	// Status / inspection
	ClusterStatus(ctx context.Context, includeNodes bool) (interface{}, error)
	ClusterListNodes(ctx context.Context) (interface{}, error)
}

// clusterProvider returns the ClusterProvider interface if the
// ServiceProvider implements it, else nil.
func (r *ToolRegistry) clusterProvider() ClusterProvider {
	if p, ok := r.service.(ClusterProvider); ok {
		return p
	}
	return nil
}

// registerClusterTools registers the platform_cluster_* MCP tools. Each
// tool definition mirrors the equivalent gRPC RPC so AI/LLM clients can
// issue the same calls they would over gRPC.
func (r *ToolRegistry) registerClusterTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_cluster_bootstrap",
		Description: "Initialize a new cluster with this node as the initial leader",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"cluster_name": map[string]interface{}{
					"type":        "string",
					"description": "Optional human-friendly cluster name surfaced in metadata",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_cluster_join",
		Description: "Join this node to an existing cluster by dialing one or more seed addresses",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"seed_addresses": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Existing cluster member addresses to dial (host:port)",
				},
			},
			"required": []string{"seed_addresses"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_cluster_leave",
		Description: "Gracefully remove this node from the cluster, transferring leadership if necessary",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_cluster_status",
		Description: "Return the current cluster status (state, leader, term, quorum). Set include_nodes=true to also enumerate members.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"include_nodes": map[string]interface{}{
					"type":        "boolean",
					"description": "When true, include the full node list and leader in the response",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_cluster_list_nodes",
		Description: "List all nodes in the cluster with their state, role, and last-seen timestamp",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// clusterToolHandler dispatches a cluster tool by name. Map-based dispatch
// keeps routing O(1) per project conventions.
type clusterToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var clusterToolDispatch = map[string]clusterToolHandler{
	"platform_cluster_bootstrap":  (*ToolRegistry).executeClusterBootstrap,
	"platform_cluster_join":       (*ToolRegistry).executeClusterJoin,
	"platform_cluster_leave":      (*ToolRegistry).executeClusterLeave,
	"platform_cluster_status":     (*ToolRegistry).executeClusterStatus,
	"platform_cluster_list_nodes": (*ToolRegistry).executeClusterListNodes,
}

// dispatchClusterTool looks up a cluster tool and invokes it. Returns
// (result, handled, err) so the caller can fall through when handled is
// false (tool name doesn't belong to cluster).
func (r *ToolRegistry) dispatchClusterTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := clusterToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeClusterBootstrap(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.clusterProvider()
	if p == nil {
		return nil, ErrClusterNotConfigured
	}
	clusterName := getString(args, "cluster_name")
	return p.ClusterBootstrap(ctx, clusterName)
}

func (r *ToolRegistry) executeClusterJoin(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.clusterProvider()
	if p == nil {
		return nil, ErrClusterNotConfigured
	}
	addresses := getStringSlice(args, "seed_addresses")
	if len(addresses) == 0 {
		return nil, ErrClusterSeedAddressRequired
	}
	return p.ClusterJoin(ctx, addresses)
}

func (r *ToolRegistry) executeClusterLeave(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.clusterProvider()
	if p == nil {
		return nil, ErrClusterNotConfigured
	}
	return p.ClusterLeave(ctx)
}

func (r *ToolRegistry) executeClusterStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.clusterProvider()
	if p == nil {
		return nil, ErrClusterNotConfigured
	}
	includeNodes := getBool(args, "include_nodes")
	return p.ClusterStatus(ctx, includeNodes)
}

func (r *ToolRegistry) executeClusterListNodes(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.clusterProvider()
	if p == nil {
		return nil, ErrClusterNotConfigured
	}
	return p.ClusterListNodes(ctx)
}

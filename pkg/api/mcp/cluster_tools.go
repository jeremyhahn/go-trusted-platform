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
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Cluster tool wiring
// =============================================================================
//
// Every gRPC ClusterService method has one platform_cluster_<verb> tool. A
// tool's arguments are the gRPC request in protojson form (proto field names,
// enums by name, 64-bit integers and bytes as JSON strings) and its result is
// the gRPC response in the same form. Each tool calls the gRPC ClusterService
// servicer, so it validates, answers and fails exactly as gRPC does. The
// scope each tool requires is in authz.go.

// ErrClusterNotConfigured indicates the cluster backend is not wired into
// the MCP tool registry: the service provider serves no gRPC ClusterService.
var ErrClusterNotConfigured = errors.New("cluster: service provider not configured")

// ClusterProvider is implemented by a ServiceProvider that serves the gRPC
// ClusterService. The platform_cluster_* tools call that servicer.
type ClusterProvider interface {
	// ClusterServiceServer returns the gRPC ClusterService servicer, or nil
	// while no cluster service is wired.
	ClusterServiceServer() platformv1.ClusterServiceServer
}

// clusterToolCall runs one cluster tool against the gRPC ClusterService
// servicer.
type clusterToolCall func(server platformv1.ClusterServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error)

// clusterToolBinding is how a cluster tool reaches the servicer: the schema
// it advertises and the call that serves it.
type clusterToolBinding struct {
	schema func() map[string]interface{}
	call   clusterToolCall
}

// clusterTool is one cluster tool and the gRPC method it serves.
type clusterTool struct {
	method      string
	description string
	binding     clusterToolBinding
}

// clusterTools are the cluster tools bound to the gRPC ClusterService.
var clusterTools = map[string]clusterTool{
	"platform_cluster_bootstrap": {
		method:      platformv1.ClusterService_Bootstrap_FullMethodName,
		description: "Initialize a new cluster with this node as the initial leader",
		binding:     clusterToolMethod(platformv1.ClusterServiceServer.Bootstrap, "cluster_name", "node_name"),
	},
	"platform_cluster_join": {
		method:      platformv1.ClusterService_Join_FullMethodName,
		description: "Join this node to an existing cluster by dialing one or more seed addresses (host:port)",
		binding:     clusterToolMethod(platformv1.ClusterServiceServer.Join, "node_name", "seed_addresses"),
	},
	"platform_cluster_leave": {
		method:      platformv1.ClusterService_Leave_FullMethodName,
		description: "Gracefully remove this node from the cluster, transferring leadership if necessary; node_id, when set, must be this node",
		binding:     clusterToolMethod(platformv1.ClusterServiceServer.Leave),
	},
	"platform_cluster_status": {
		method:      platformv1.ClusterService_GetStatus_FullMethodName,
		description: "Return the current cluster status (state, leader, term, quorum). Set include_nodes=true to also enumerate members.",
		binding:     clusterToolMethod(platformv1.ClusterServiceServer.GetStatus),
	},
	"platform_cluster_list_nodes": {
		method:      platformv1.ClusterService_ListNodes_FullMethodName,
		description: "List the cluster nodes, filtered by role, state and labels, sorted and paginated",
		binding:     clusterToolMethod(platformv1.ClusterServiceServer.ListNodes),
	},
}

// clusterToolMethod binds a cluster tool to one ClusterService method: the
// arguments decode into its request and its response is the tool result.
func clusterToolMethod[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	call func(platformv1.ClusterServiceServer, context.Context, PReq) (Resp, error),
	required ...string,
) clusterToolBinding {
	descriptor := PReq(new(Req)).ProtoReflect().Descriptor()
	return clusterToolBinding{
		schema: func() map[string]interface{} {
			return appToolSchema(descriptor, required...)
		},
		call: func(server platformv1.ClusterServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error) {
			request := PReq(new(Req))
			if err := decodeAppToolArgs(args, request); err != nil {
				return nil, err
			}
			response, err := call(server, ctx, request)
			if err != nil {
				return nil, err
			}
			return encodeAppToolResult(response)
		},
	}
}

// registerClusterTools registers the platform_cluster_* tools.
func (r *ToolRegistry) registerClusterTools() {
	for _, name := range slices.Sorted(maps.Keys(clusterTools)) {
		tool := clusterTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// clusterServiceServer is the gRPC ClusterService servicer the cluster tools
// call, or nil while the service provider serves none.
func (r *ToolRegistry) clusterServiceServer() platformv1.ClusterServiceServer {
	if provider, ok := r.service.(ClusterProvider); ok {
		return provider.ClusterServiceServer()
	}
	return nil
}

// dispatchClusterTool runs a platform_cluster_* tool. handled is false when
// name is not a cluster tool, so the caller tries the next dispatcher.
func (r *ToolRegistry) dispatchClusterTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := clusterTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.clusterServiceServer()
	if server == nil {
		return nil, true, ErrClusterNotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}

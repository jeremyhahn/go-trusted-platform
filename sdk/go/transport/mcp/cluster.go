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

// The platform_cluster_* tools (pkg/api/mcp/cluster_tools.go, #704) call the
// daemon's gRPC ClusterService servicer: they take the request and return the
// response in the proto3 JSON mapping with proto field names, so the shared
// protoJSON builder and decoder serve every method.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// clusterToolMap maps each ClusterService gRPC method to the platformd MCP
// tool that serves it.
var clusterToolMap = map[string]string{
	platformv1.ClusterService_Bootstrap_FullMethodName: "platform_cluster_bootstrap",
	platformv1.ClusterService_Join_FullMethodName:      "platform_cluster_join",
	platformv1.ClusterService_Leave_FullMethodName:     "platform_cluster_leave",
	platformv1.ClusterService_GetStatus_FullMethodName: "platform_cluster_status",
	platformv1.ClusterService_ListNodes_FullMethodName: "platform_cluster_list_nodes",
}

func init() {
	for method, tool := range clusterToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}

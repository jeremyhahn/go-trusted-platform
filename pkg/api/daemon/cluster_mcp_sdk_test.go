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
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// connectClusterMCP serves server through the daemon's MCP server and
// connects the SDK's MCP adapter as a caller holding scopes.
func connectClusterMCP(t *testing.T, server platformv1.ClusterServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	provider := &MCPServiceProvider{}
	provider.SetClusterServer(server)
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: &platformtoken.AuthorizedContext{
		Subject: "operator",
		Scopes:  scopes,
	}}}
	return serveMCPConfig(t, provider, config).Connection()
}

// TestSDKMCP_ClusterMethods drives every ClusterService method through the
// SDK's MCP adapter and the daemon's platform_cluster_* tools.
func TestSDKMCP_ClusterMethods(t *testing.T) {
	testSDKClusterMethods(t, "MCP", connectClusterMCP)
}

// TestSDKMCP_ClusterMethodsRefuse checks the MCP path refuses a missing scope
// and a cluster refusal with the codes gRPC gives.
func TestSDKMCP_ClusterMethodsRefuse(t *testing.T) {
	testSDKClusterRefusesScope(t, "MCP", connectClusterMCP)
	testSDKClusterRefusesService(t, "MCP", connectClusterMCP)
}

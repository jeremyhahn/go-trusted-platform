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
	"path"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// serveSwitchMCP serves provider through the daemon's MCP server and
// connects the SDK's MCP adapter as a caller holding scopes.
func serveSwitchMCP(t *testing.T, provider *MCPServiceProvider, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: &platformtoken.AuthorizedContext{
		Subject: "operator",
		Scopes:  scopes,
	}}}
	return serveMCPConfig(t, provider, config).Connection()
}

// connectSwitchMCP wires server as the MCP provider's switch servicer and
// connects the SDK's MCP adapter to it.
func connectSwitchMCP(t *testing.T, server platformv1.SwitchServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	provider := &MCPServiceProvider{}
	provider.SetSwitchServer(server)
	return serveSwitchMCP(t, provider, scopes...)
}

// TestSDKMCP_SwitchMethods drives every SwitchService method through the
// SDK's MCP adapter and the daemon's MCP server.
func TestSDKMCP_SwitchMethods(t *testing.T) {
	testSDKSwitchMethods(t, "MCP", connectSwitchMCP)
}

// TestSDKMCP_SwitchMethodsRefuse checks the MCP path refuses a missing scope
// and a missing port with the codes gRPC gives.
func TestSDKMCP_SwitchMethodsRefuse(t *testing.T) {
	testSDKSwitchRefusesScope(t, "MCP", connectSwitchMCP)
	testSDKSwitchRefusesNotFound(t, "MCP", connectSwitchMCP)
}

// TestSwitchMCPUnwiredAnswersUnavailable checks that a daemon serving no
// SwitchService answers every switch method over MCP as not configured
// (Unavailable), the class the servicer gives with no backend, and never
// dereferences a nil servicer.
func TestSwitchMCPUnwiredAnswersUnavailable(t *testing.T) {
	conn := serveSwitchMCP(t, &MCPServiceProvider{}, "*:*")
	for method, req := range switchSDKRequests("eth1") {
		t.Run(path.Base(method), func(t *testing.T) {
			err := conn.Invoke(context.Background(), method, req, switchSDKReplies()[method])
			require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		})
	}
}

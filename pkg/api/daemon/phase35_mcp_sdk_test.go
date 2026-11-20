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
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)

// phase35MCPToken is the only bearer token tokenGrantAuthz accepts.
const phase35MCPToken = "phase35-mcp-token"

// tokenGrantAuthz grants every permission to phase35MCPToken and nothing
// to any other caller, so the tools run behind the server's real
// authorization check.
type tokenGrantAuthz struct{}

func (tokenGrantAuthz) CheckPermission(_ context.Context, subject, _, _ string) (bool, error) {
	return subject == phase35MCPToken, nil
}

// ValidateToken and GetTokenClaims make tokenGrantAuthz the AuthManager too:
// the token is the caller, and the IAM PEP decides its tool permission (#1995).
func (tokenGrantAuthz) ValidateToken(_ context.Context, token string) (bool, error) {
	return token == phase35MCPToken, nil
}

func (tokenGrantAuthz) GetTokenClaims(_ context.Context, token string) (map[string]interface{}, error) {
	// The PEP path refuses a caller with no tenant before asking the PEP
	// (#2011 Codex), so the caller carries one.
	return map[string]interface{}{"sub": token, "tenant_id": phase35MCPTenant}, nil
}

// phase35MCPTenant is the tenant of the phase35MCPToken caller.
const phase35MCPTenant = "phase35-tenant"

// newPhase35MCPClient serves the daemon's MCP provider through the MCP
// server's HTTP routes and connects the SDK's MCP adapter to it, so a call
// travels the client's tool name and arguments through the server's tool
// registry and the provider's translation and back.
func newPhase35MCPClient(t *testing.T, svcs Phase35Services) *sdkmcp.Adapter {
	t.Helper()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	provider.SetPhase35Services(svcs)
	return serveMCPProvider(t, provider)
}

// serveMCPProvider serves a daemon MCP provider through the MCP server's
// HTTP routes and connects the SDK's MCP adapter to it.
func serveMCPProvider(t *testing.T, provider *MCPServiceProvider) *sdkmcp.Adapter {
	t.Helper()
	config := mcp.DefaultConfig()
	config.AuthorizationService = tokenGrantAuthz{}
	config.AuthManager = tokenGrantAuthz{}
	// checks counts the PEP's decisions: a test whose tool calls never
	// reached the PEP was refused before it (no tenant, no caller), and its
	// denials would pass for the wrong reason.
	var checks atomic.Int32
	config.PEPClient = &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		checks.Add(1)
		return &sdkiam.CheckResponse{Allowed: req.Subject.ID == phase35MCPToken && req.Subject.TenantID == phase35MCPTenant}, nil
	}}
	t.Cleanup(func() {
		if checks.Load() == 0 {
			t.Error("no MCP tool call reached the IAM PEP")
		}
	})
	return serveMCPConfig(t, provider, config)
}

// serveMCPConfig serves provider through an MCP server built from config and
// connects the SDK's MCP adapter to it with phase35MCPToken.
func serveMCPConfig(t *testing.T, provider *MCPServiceProvider, config *mcp.Config) *sdkmcp.Adapter {
	t.Helper()

	// The daemon serves MCP over TLS 1.3 only, and the SDK sends a bearer
	// token over https:// only.
	server := httptest.NewUnstartedServer(mcp.NewServer(provider, config, logging.DefaultLogger()).Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	conn, err := sdkmcp.Connect(context.Background(), platform.NewOptions(
		platform.WithMCPAddr(server.URL),
		platform.WithTLSConfig(phase35ClientTLS(server)),
		platform.WithBearerToken(phase35MCPToken),
	))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	a, ok := conn.(*sdkmcp.Adapter)
	if !ok {
		t.Fatalf("Connect returned %T, want *mcp.Adapter", conn)
	}
	return a
}

// TestPhase35MCPClientAgainstDaemonServer drives every ceremony, PIV and
// FIDO2 method of the SDK MCP client through the MCP server into the
// daemon's provider. A tool the server does not register, an argument the
// provider cannot read, or a result the client cannot translate fails here.
func TestPhase35MCPClientAgainstDaemonServer(t *testing.T) {
	ceremony, piv, fido := phase35Services()
	a := newPhase35MCPClient(t, Phase35Services{Ceremony: ceremony, PIV: piv, FIDO2: fido})

	runPhase35SDKCases(t, a.Connection())
}

// TestPhase35MCPClientAgainstDaemonServer_ServerErrorsSurface proves a
// daemon without the service answers the MCP client with an error rather
// than an empty reply.
func TestPhase35MCPClientAgainstDaemonServer_ServerErrorsSurface(t *testing.T) {
	a := newPhase35MCPClient(t, Phase35Services{})

	err := a.Connection().Invoke(context.Background(), platformv1.PIVService_ListDevices_FullMethodName,
		&platformv1.PIVListDevicesRequest{}, &platformv1.PIVListDevicesResponse{})
	if status.Code(err) == codes.OK || !strings.Contains(status.Convert(err).Message(), "piv: backend not configured") {
		t.Errorf("err = %v, want the daemon's missing PIV backend", err)
	}
}

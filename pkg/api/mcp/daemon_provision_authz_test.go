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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// daemonProvisionToolScopes pins each classified daemon and provisioning
// tool (#304) to the scope of its gRPC twin in method_permissions.go.
// list_protocols has no gRPC twin; it takes QUIC's OpDaemonListProtocols
// scope from opcode_permissions.go.
var daemonProvisionToolScopes = map[string]string{
	"platform_daemon_status":         "platform:read",
	"platform_daemon_version":        "platform:read",
	"platform_daemon_list_services":  "platform:read",
	"platform_daemon_list_protocols": "platform:read",
	"platform_daemon_get_service":    "platform:read",

	"platform_daemon_start_service":   "platform:write",
	"platform_daemon_stop_service":    "platform:write",
	"platform_daemon_restart_service": "platform:write",

	"provision_list_sessions":   "provisioning:read",
	"provision_get_session":     "provisioning:read",
	"provision_fulfill_session": "provisioning:write",
}

// provisionOpenTools are open on gRPC ConfigDeliveryService too: the shared
// configdelivery.Service checks the device's proof itself.
var provisionOpenTools = map[string]string{
	"provision_get_nonce":    "get_nonce",
	"provision_fetch_config": "fetch_config",
	"provision_sign_digest":  "sign_digest",
	"provision_poll_session": "poll_session",
}

// daemonProvisionStubCall is the call each scoped tool's handler records.
var daemonProvisionStubCall = map[string]string{
	"platform_daemon_status":          "platform_daemon_status",
	"platform_daemon_version":         "platform_daemon_version",
	"platform_daemon_list_services":   "platform_daemon_list_services",
	"platform_daemon_list_protocols":  "platform_daemon_list_protocols",
	"platform_daemon_get_service":     "platform_daemon_get_service",
	"platform_daemon_start_service":   "platform_daemon_start_service",
	"platform_daemon_stop_service":    "platform_daemon_stop_service",
	"platform_daemon_restart_service": "platform_daemon_restart_service",
	"provision_list_sessions":         "list_sessions",
	"provision_get_session":           "get_session",
	"provision_fulfill_session":       "fulfill_session",
}

// daemonProvisionServer returns a server whose caller holds only scope, and
// the stub its daemon and provisioning handlers record calls on.
func daemonProvisionServer(scope string) (*Server, *provisionStubProvider) {
	stub := &provisionStubProvider{}
	mock := newMockServiceProvider()
	record := func(tool string) func(context.Context) (interface{}, error) {
		return func(context.Context) (interface{}, error) {
			stub.lastCall = tool
			return map[string]interface{}{}, nil
		}
	}
	recordNamed := func(tool string) func(context.Context, string) (interface{}, error) {
		return func(context.Context, string) (interface{}, error) {
			stub.lastCall = tool
			return map[string]interface{}{}, nil
		}
	}
	mock.daemonStatusFunc = record("platform_daemon_status")
	mock.daemonVersionFunc = record("platform_daemon_version")
	mock.daemonListServicesFunc = record("platform_daemon_list_services")
	mock.daemonListProtocolsFunc = record("platform_daemon_list_protocols")
	mock.daemonGetServiceFunc = recordNamed("platform_daemon_get_service")
	mock.daemonStartServiceFunc = recordNamed("platform_daemon_start_service")
	mock.daemonStopServiceFunc = recordNamed("platform_daemon_stop_service")
	mock.daemonRestartServiceFunc = recordNamed("platform_daemon_restart_service")

	svc := &provisionCombinedProvider{mockServiceProvider: mock, provisionStubProvider: stub}
	server := NewServer(svc, nil, newTestLogger())
	server.SetAuthorizationService(scopeChecker(scope), &mockAuthManager{})
	return server, stub
}

// daemonProvisionToolCall calls tool with arguments every daemon and
// provisioning handler accepts. An empty token sends none.
func daemonProvisionToolCall(server *Server, tool, token string) *mcpwire.JSONRPCResponse {
	arguments := map[string]interface{}{
		"name":       "tpm",
		"session_id": "session-1",
		"profile_id": float64(42),
		"ek_serial":  "ek-1",
		"eab_key_id": "key-1",
		"eab_hmac":   "hmac",
		"nonce":      "nonce-1",
		"digest":     "ZGlnZXN0",
	}
	if token != "" {
		arguments["_token"] = token
	}
	return server.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]interface{}{"name": tool, "arguments": arguments},
	})
}

func TestDaemonProvisionToolPermissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	for tool, want := range daemonProvisionToolScopes {
		if got, ok := checker.toolPermissions[tool]; !ok || got != want {
			t.Errorf("permission for %s = %q (mapped %v), want %q", tool, got, ok, want)
		}
	}
	for tool := range provisionOpenTools {
		if got, ok := checker.toolPermissions[tool]; !ok || got != "" {
			t.Errorf("permission for %s = %q (mapped %v), want open", tool, got, ok)
		}
	}
}

func TestDaemonProvisionAuthorizeToolEnforcesScope(t *testing.T) {
	ctx := context.Background()
	scopes := []string{"platform:read", "platform:write", "provisioning:read", "provisioning:write"}
	for tool, want := range daemonProvisionToolScopes {
		for _, held := range scopes {
			checker := NewAuthorizationChecker(scopeChecker(held), &mockAuthManager{})
			_, authErr := checker.AuthorizeTool(ctx, tool, "tok")
			if held == want {
				if authErr != nil {
					t.Errorf("%s refused for a caller holding %s: %s", tool, held, authErr.Message)
				}
				continue
			}
			if authErr == nil || authErr.Type != AuthErrorPermissionDenied {
				t.Errorf("%s with only %s: err = %+v, want permission denied", tool, held, authErr)
			}
		}
	}
}

func TestDaemonProvisionToolsCall_ScopeGatesHandler(t *testing.T) {
	for tool, scope := range daemonProvisionToolScopes {
		t.Run(tool, func(t *testing.T) {
			server, stub := daemonProvisionServer(scope)
			if resp := daemonProvisionToolCall(server, tool, "tok"); resp.Error != nil {
				t.Fatalf("with %s: error %d %s", scope, resp.Error.Code, resp.Error.Message)
			}
			if stub.lastCall != daemonProvisionStubCall[tool] {
				t.Errorf("with %s: handler %q ran, want %q", scope, stub.lastCall, daemonProvisionStubCall[tool])
			}

			server, stub = daemonProvisionServer("platform:none")
			resp := daemonProvisionToolCall(server, tool, "tok")
			if resp.Error == nil || resp.Error.Code != mcpwire.PermissionDenied {
				t.Errorf("without %s: response %+v, want permission denied", scope, resp.Error)
			}
			if stub.lastCall != "" {
				t.Errorf("without %s: handler %q ran, want none", scope, stub.lastCall)
			}
		})
	}
}

func TestProvisionOpenToolsCall_RunWithoutToken(t *testing.T) {
	for tool, call := range provisionOpenTools {
		t.Run(tool, func(t *testing.T) {
			server, stub := daemonProvisionServer("platform:none")
			if resp := daemonProvisionToolCall(server, tool, ""); resp.Error != nil {
				t.Fatalf("error %d %s, want the open tool to run", resp.Error.Code, resp.Error.Message)
			}
			if stub.lastCall != call {
				t.Errorf("handler %q ran, want %q", stub.lastCall, call)
			}
		})
	}
}

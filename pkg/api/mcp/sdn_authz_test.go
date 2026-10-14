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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// sdnToolScopes is the scope each classified SDN tool carries: the action of
// its gRPC twin in pkg/api/grpc/method_permissions.go, on resource "sdn".
var sdnToolScopes = map[string]string{
	"sdn_add_flow":       "write",
	"sdn_delete_flow":    "delete",
	"sdn_flush_flows":    "write",
	"sdn_list_flows":     "read",
	"sdn_get_flow_stats": "read",
	"sdn_create_vlan":    "write",
	"sdn_delete_vlan":    "delete",
	"sdn_list_vlans":     "read",
	"sdn_get_port_stats": "read",
}

func TestSDNToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for tool, action := range sdnToolScopes {
		if got, want := checker.toolPermissions[tool], "sdn:"+action; got != want {
			t.Errorf("%s permission = %q, want %q", tool, got, want)
		}
	}

	// The port-auth tools record a map entry and never reach the switch, so
	// they stay refused rather than answer a fake success under a scope.
	for _, tool := range []string{"sdn_authenticate_port", "sdn_revoke_port_auth"} {
		if perm, ok := checker.toolPermissions[tool]; ok {
			t.Errorf("%s is classified as %q; it must stay refused", tool, perm)
		}
	}
}

// sdnServiceRecordingCalls returns a mock service whose SDN calls record the
// tool that reached the service, so a test can tell whether the handler ran.
func sdnServiceRecordingCalls(ran map[string]bool) *mockServiceProvider {
	svc := newMockServiceProvider()
	svc.sdnAddFlowFunc = func(_ context.Context, _ string, _ map[string]interface{}) (interface{}, error) {
		ran["sdn_add_flow"] = true
		return map[string]interface{}{"id": "0x1"}, nil
	}
	svc.sdnDeleteFlowFunc = func(_ context.Context, _, _ string) error {
		ran["sdn_delete_flow"] = true
		return nil
	}
	svc.sdnFlushFlowsFunc = func(_ context.Context, _ string) (uint32, error) {
		ran["sdn_flush_flows"] = true
		return 0, nil
	}
	svc.sdnListFlowsFunc = func(_ context.Context, _ string) ([]interface{}, error) {
		ran["sdn_list_flows"] = true
		return []interface{}{}, nil
	}
	svc.sdnGetFlowStatsFunc = func(_ context.Context, _, _ string) (interface{}, error) {
		ran["sdn_get_flow_stats"] = true
		return map[string]interface{}{}, nil
	}
	svc.sdnCreateVLANFunc = func(_ context.Context, _ string, vlanID int, name string) (interface{}, error) {
		ran["sdn_create_vlan"] = true
		return map[string]interface{}{"vlan_id": vlanID, "name": name}, nil
	}
	svc.sdnDeleteVLANFunc = func(_ context.Context, _ string, _ int) error {
		ran["sdn_delete_vlan"] = true
		return nil
	}
	svc.sdnListVLANsFunc = func(_ context.Context, _ string) ([]interface{}, error) {
		ran["sdn_list_vlans"] = true
		return []interface{}{}, nil
	}
	svc.sdnGetPortStatsFunc = func(_ context.Context, _, _ string) (interface{}, error) {
		ran["sdn_get_port_stats"] = true
		return map[string]interface{}{}, nil
	}
	return svc
}

// callSDNTool calls one SDN tool through the server, as a caller granted only
// the given sdn actions.
func callSDNTool(t *testing.T, tool string, granted ...string) (*mcpwire.JSONRPCResponse, map[string]bool) {
	t.Helper()

	ran := map[string]bool{}
	authMgr := &mockAuthManager{
		validateFunc: func(context.Context, string) (bool, error) { return true, nil },
	}
	authSvc := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			if resource != "sdn" {
				return false, nil
			}
			for _, g := range granted {
				if action == g {
					return true, nil
				}
			}
			return false, nil
		},
	}
	server := NewServer(sdnServiceRecordingCalls(ran), &Config{
		AuthManager:          authMgr,
		AuthorizationService: authSvc,
	}, newTestLogger())

	req := &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": tool,
			"arguments": map[string]interface{}{
				"bridge_name": "br0",
				"flow_id":     "0x1",
				"port_name":   "eth0",
				"vlan_id":     float64(100),
				"name":        "vlan100",
				"_token":      "token",
			},
		},
	}
	return server.handleRequest(context.Background(), req), ran
}

// TestSDNPortAuthToolsRefuse pins the port-auth tools to a typed refusal.
// Before #304 they answered {"success": true} for a port the switch never
// admitted or blocked.
func TestSDNPortAuthToolsRefuse(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	args := map[string]interface{}{
		"bridge_name": "br0",
		"port_name":   "eth0",
		"credentials": map[string]interface{}{"certificate": "-----BEGIN CERTIFICATE-----"},
	}

	for _, tool := range []string{"sdn_authenticate_port", "sdn_revoke_port_auth"} {
		t.Run(tool, func(t *testing.T) {
			result, err := registry.ExecuteTool(context.Background(), tool, args)
			if result != nil {
				t.Errorf("refused tool answered %v", result)
			}
			var refusal ErrPortAuthNotEnforced
			if !errors.As(err, &refusal) {
				t.Fatalf("error = %v, want ErrPortAuthNotEnforced", err)
			}
			if refusal.Tool != tool {
				t.Errorf("refusal names %q, want %q", refusal.Tool, tool)
			}
			if got := status.Code(err); got != codes.FailedPrecondition {
				t.Errorf("class = %v, want FailedPrecondition", got)
			}
			if got, want := toolErrorCode(err), mcpwire.CodeForClass(codes.FailedPrecondition); got != want {
				t.Errorf("wire code = %d, want %d", got, want)
			}
		})
	}
}

func TestSDNToolsAuthorizeByScope(t *testing.T) {
	for tool, action := range sdnToolScopes {
		t.Run(tool+"/granted", func(t *testing.T) {
			resp, ran := callSDNTool(t, tool, action)
			if resp.Error != nil {
				t.Fatalf("caller holding sdn:%s was refused: %v", action, resp.Error)
			}
			if !ran[tool] {
				t.Errorf("caller holding sdn:%s never reached the service", action)
			}
		})

		t.Run(tool+"/denied", func(t *testing.T) {
			var others []string
			for _, a := range []string{"read", "write", "delete"} {
				if a != action {
					others = append(others, a)
				}
			}
			resp, ran := callSDNTool(t, tool, others...)
			if resp.Error == nil {
				t.Fatalf("caller without sdn:%s was answered", action)
			}
			if resp.Error.Code != mcpwire.PermissionDenied {
				t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.PermissionDenied)
			}
			if ran[tool] {
				t.Errorf("handler ran for a caller without sdn:%s", action)
			}
		})
	}
}

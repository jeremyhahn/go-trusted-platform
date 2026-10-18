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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// luksToolScopes is the scope of every classified LUKS tool, the same as its
// gRPC LUKSService twin in pkg/api/grpc/method_permissions.go.
var luksToolScopes = map[string]string{
	"platform_luks_status":     "luks:read",
	"platform_luks_list_slots": "luks:read",
	"platform_luks_info":       "luks:read",

	"platform_luks_enroll_passphrase": "luks:write",
	"platform_luks_enroll_fido2":      "luks:write",
	"platform_luks_enroll_tpm":        "luks:write",
	"platform_luks_enroll_recovery":   "luks:write",
	"platform_luks_change_passphrase": "luks:write",

	"platform_luks_remove_key": "luks:delete",
}

// luksTestUnlockTool tries no key material, so it stays unclassified.
const luksTestUnlockTool = "platform_luks_test_unlock"

// luksStubCall is the phase35StubProvider method each LUKS tool reaches.
var luksStubCall = map[string]string{
	"platform_luks_status":            "luks_status",
	"platform_luks_list_slots":        "luks_list_slots",
	"platform_luks_info":              "luks_info",
	"platform_luks_enroll_passphrase": "luks_enroll_passphrase",
	"platform_luks_enroll_fido2":      "luks_enroll_fido2",
	"platform_luks_enroll_tpm":        "luks_enroll_tpm",
	"platform_luks_enroll_recovery":   "luks_enroll_recovery",
	"platform_luks_change_passphrase": "luks_change_passphrase",
	"platform_luks_remove_key":        "luks_remove_key",
}

// scopeChecker grants exactly one "resource:action" scope.
func scopeChecker(scope string) *mockAuthorizationService {
	return &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return resource+":"+action == scope, nil
		},
	}
}

func TestLUKSToolPermissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	for tool, want := range luksToolScopes {
		if got := checker.toolPermissions[tool]; got != want {
			t.Errorf("permission for %s = %q, want %q", tool, got, want)
		}
	}
	if scope, ok := checker.toolPermissions[luksTestUnlockTool]; ok {
		t.Errorf("%s is classified as %q; it tries no key and must stay unclassified", luksTestUnlockTool, scope)
	}
}

// TestLUKSToolsAreRegisteredAndScoped fails when a LUKS tool is registered
// that is neither scoped nor the unclassified test-unlock.
func TestLUKSToolsAreRegisteredAndScoped(t *testing.T) {
	registry := NewToolRegistry(nil, nil)
	registered := 0
	for _, tool := range registry.ListTools() {
		if !strings.HasPrefix(tool.Name, "platform_luks_") || tool.Name == luksTestUnlockTool {
			continue
		}
		if _, ok := luksToolScopes[tool.Name]; !ok {
			t.Errorf("%s is registered without a scope in luksToolScopes", tool.Name)
			continue
		}
		registered++
	}
	if registered != len(luksToolScopes) {
		t.Errorf("registry exposes %d of the %d scoped LUKS tools", registered, len(luksToolScopes))
	}
}

// TestLUKSAuthorizeToolEnforcesScope allows each tool for a caller holding
// its scope and denies it for a caller holding any other LUKS scope.
func TestLUKSAuthorizeToolEnforcesScope(t *testing.T) {
	ctx := context.Background()
	scopes := []string{"luks:read", "luks:write", "luks:delete"}
	for tool, want := range luksToolScopes {
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

func TestLUKSTestUnlockIsRefusedUnclassified(t *testing.T) {
	checker := NewAuthorizationChecker(scopeChecker("luks:read"), &mockAuthManager{})
	_, authErr := checker.AuthorizeTool(context.Background(), luksTestUnlockTool, "tok")
	if authErr == nil || authErr.Type != AuthErrorToolNotClassified {
		t.Errorf("err = %+v, want tool not classified", authErr)
	}
}

// luksToolCall sends one tools/call through the server, as a client would.
func luksToolCall(server *Server, tool string) *mcpwire.JSONRPCResponse {
	return server.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": tool,
			"arguments": map[string]interface{}{
				"_token":              "tok",
				"device":              "/dev/sda",
				"existing_passphrase": "x",
				"slot":                float64(1),
			},
		},
	})
}

// luksServer builds a server whose caller holds only scope.
func luksServer(scope string) (*Server, *phase35StubProvider) {
	stub := &phase35StubProvider{}
	svc := &phase35CombinedProvider{mockServiceProvider: newMockServiceProvider(), phase35StubProvider: stub}
	server := NewServer(svc, nil, newTestLogger())
	server.SetAuthorizationService(scopeChecker(scope), &mockAuthManager{})
	return server, stub
}

// TestLUKSToolsCall_ScopeGatesHandler drives tools/call end to end: with
// the scope the tool's handler answers; without it the caller gets the
// permission error and the handler never runs.
func TestLUKSToolsCall_ScopeGatesHandler(t *testing.T) {
	for tool, scope := range luksToolScopes {
		t.Run(tool, func(t *testing.T) {
			server, stub := luksServer(scope)
			if resp := luksToolCall(server, tool); resp.Error != nil {
				t.Fatalf("with %s: error %d %s", scope, resp.Error.Code, resp.Error.Message)
			}
			if stub.lastCall != luksStubCall[tool] {
				t.Errorf("with %s: handler %q ran, want %q", scope, stub.lastCall, luksStubCall[tool])
			}

			server, stub = luksServer("luks:none")
			resp := luksToolCall(server, tool)
			if resp.Error == nil || resp.Error.Code != mcpwire.PermissionDenied {
				t.Errorf("without %s: response %+v, want permission denied", scope, resp.Error)
			}
			if stub.lastCall != "" {
				t.Errorf("without %s: handler %q ran, want none", scope, stub.lastCall)
			}
		})
	}
}

func TestLUKSToolsCall_TestUnlockNeverRuns(t *testing.T) {
	server, stub := luksServer("luks:read")
	resp := luksToolCall(server, luksTestUnlockTool)
	if resp.Error == nil {
		t.Fatal("test-unlock answered; want refusal")
	}
	if stub.lastCall != "" {
		t.Errorf("handler %q ran, want none", stub.lastCall)
	}
}

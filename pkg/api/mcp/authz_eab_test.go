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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// eabToolScopes is each EAB tool's required eab action — the scope of its
// gRPC EABService twin in pkg/api/grpc/method_permissions.go — with the
// arguments that make the tool reach its provider and the provider call
// that proves it ran.
var eabToolScopes = []struct {
	tool     string
	action   string
	args     map[string]interface{}
	wantCall string
}{
	{"platform_eab_create_credential", "write", map[string]interface{}{"profile_id": 7, "tenant_id": "tenant-1"}, "create"},
	{"platform_eab_revoke_credential", "write", map[string]interface{}{"credential_id": 42}, "revoke"},
	{"platform_eab_mark_credential_used", "write", map[string]interface{}{"credential_id": 42}, "mark_used"},
	{"platform_eab_cleanup_expired_credentials", "write", map[string]interface{}{"tenant_id": "tenant-1"}, "cleanup"},
	{"platform_eab_get_credential", "read", map[string]interface{}{"credential_id": 42}, "get"},
	{"platform_eab_get_credential_by_key_id", "read", map[string]interface{}{"key_id": "k-abc"}, "get_by_key_id"},
	{"platform_eab_list_credentials", "read", map[string]interface{}{}, "list"},
	{"platform_eab_validate_credential", "read", map[string]interface{}{"key_id": "k-abc", "hmac_key": "AAECAwQF"}, "validate"},
	{"platform_eab_get_credential_qr_code", "read", map[string]interface{}{"credential_id": 42}, "qr"},
	{"platform_eab_get_enrollment_url", "read", map[string]interface{}{"credential_id": 42}, "url"},
	{"platform_eab_delete_credential", "delete", map[string]interface{}{"credential_id": 42}, "delete"},
}

// eabScopeGrant authorizes exactly one eab action and nothing else.
func eabScopeGrant(action string) *mockAuthorizationService {
	return &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, granted string) (bool, error) {
			return resource == "eab" && granted == action, nil
		},
	}
}

// eabOtherAction names an eab action that is not the given one, so a
// caller holding a sibling EAB scope is the one denied.
func eabOtherAction(action string) string {
	if action == "read" {
		return "write"
	}
	return "read"
}

func TestEABToolsCarryGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	for _, tc := range eabToolScopes {
		assert.Equal(t, "eab:"+tc.action, permissions[tc.tool], tc.tool)
	}
}

// callEABTool sends one tools/call through the server, so the
// authorization gate and the handler run exactly as a client reaches them.
func callEABTool(t *testing.T, grant *mockAuthorizationService, tool string, args map[string]interface{}) (*mcpwire.JSONRPCResponse, *eabStubProvider) {
	t.Helper()
	stub := &eabStubProvider{}
	svc := &eabCombinedProvider{mockServiceProvider: newMockServiceProvider(), eabStubProvider: stub}
	server := NewServer(svc, &Config{AuthorizationService: grant}, newTestLogger())

	arguments := map[string]interface{}{"_token": "caller-token"}
	for key, value := range args {
		arguments[key] = value
	}
	req := &mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]interface{}{"name": tool, "arguments": arguments},
	}
	return server.handleRequest(context.Background(), req), stub
}

func TestEABToolAnswersUnderItsScope(t *testing.T) {
	for _, tc := range eabToolScopes {
		t.Run(tc.tool, func(t *testing.T) {
			resp, stub := callEABTool(t, eabScopeGrant(tc.action), tc.tool, tc.args)
			require.Nil(t, resp.Error, "eab:%s must authorize %s", tc.action, tc.tool)
			assert.NotNil(t, resp.Result)
			assert.Equal(t, tc.wantCall, stub.lastCall)
		})
	}
}

func TestEABToolDeniedWithoutItsScope(t *testing.T) {
	for _, tc := range eabToolScopes {
		t.Run(tc.tool, func(t *testing.T) {
			grant := eabScopeGrant(eabOtherAction(tc.action))
			resp, stub := callEABTool(t, grant, tc.tool, tc.args)
			require.NotNil(t, resp.Error, "%s must be refused without eab:%s", tc.tool, tc.action)
			assert.Equal(t, authErrorCodes[AuthErrorPermissionDenied], resp.Error.Code)
			assert.Equal(t, tc.action, grant.lastAction, "the gate must ask for eab:%s", tc.action)
			assert.Empty(t, stub.lastCall, "the handler must not run on a denied call")
		})
	}
}

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
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// vpnToolCases maps every VPN tool to its arguments and the provider call it
// must make.
var vpnToolCases = []struct {
	tool string
	args map[string]interface{}
	want mockVPNCall
}{
	{
		tool: "vpn_peer_enrol",
		args: map[string]interface{}{"tenant_id": "acme", "device_id": "laptop-1", "zones": []interface{}{"management"}},
		want: mockVPNCall{op: "enrol", args: []interface{}{"acme", "laptop-1", []string{"management"}}},
	},
	{
		tool: "vpn_peer_list",
		args: map[string]interface{}{"tenant_id": "acme"},
		want: mockVPNCall{op: "list-peers", args: []interface{}{"acme"}},
	},
	{
		tool: "vpn_peer_revoke",
		args: map[string]interface{}{"tenant_id": "acme", "device_id": "laptop-1"},
		want: mockVPNCall{op: "revoke", args: []interface{}{"acme", "laptop-1"}},
	},
	{
		tool: "vpn_status",
		args: map[string]interface{}{"gateway_id": "gw-1"},
		want: mockVPNCall{op: "status", args: []interface{}{"gw-1"}},
	},
	{
		tool: "vpn_posture_policy_get",
		args: map[string]interface{}{"tenant_id": "acme", "name": "corp"},
		want: mockVPNCall{op: "policy-get", args: []interface{}{"acme", "corp"}},
	},
	{
		tool: "vpn_posture_policy_set",
		args: map[string]interface{}{"tenant_id": "acme", "name": "corp", "module": "package vpn.posture"},
		want: mockVPNCall{op: "policy-set", args: []interface{}{"acme", "corp", "package vpn.posture"}},
	},
	{
		tool: "vpn_posture_policy_delete",
		args: map[string]interface{}{"tenant_id": "acme", "name": "corp"},
		want: mockVPNCall{op: "policy-delete", args: []interface{}{"acme", "corp"}},
	},
	{
		tool: "vpn_posture_policy_list",
		args: map[string]interface{}{"tenant_id": "acme"},
		want: mockVPNCall{op: "policy-list", args: []interface{}{"acme"}},
	},
}

func TestVPNToolsAreRegisteredWithSchemasAndScopes(t *testing.T) {
	registry := NewToolRegistry(&mockServiceProvider{}, nil)

	byName := make(map[string]mcpwire.ToolDefinition)
	for _, tool := range registry.ListTools() {
		byName[tool.Name] = tool
	}

	for _, tc := range vpnToolCases {
		tool, ok := byName[tc.tool]
		if !ok {
			t.Fatalf("tool %q is not registered", tc.tool)
		}
		if tool.Description == "" {
			t.Fatalf("tool %q has no description", tc.tool)
		}
		if tool.InputSchema["type"] != "object" {
			t.Fatalf("tool %q schema = %v, want an object", tc.tool, tool.InputSchema)
		}
	}
	if len(vpnToolExecutors) != len(vpnToolCases) {
		t.Fatalf("executors = %d, test cases = %d; every tool needs a case", len(vpnToolExecutors), len(vpnToolCases))
	}
}

func TestVPNToolsRouteTheirArgumentsToTheProvider(t *testing.T) {
	for _, tc := range vpnToolCases {
		t.Run(tc.tool, func(t *testing.T) {
			provider := &mockServiceProvider{}
			registry := NewToolRegistry(provider, nil)

			result, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args)
			if err != nil {
				t.Fatalf("%s error = %v", tc.tool, err)
			}
			if _, ok := result.(map[string]interface{}); !ok {
				t.Fatalf("%s result = %T, want a JSON object", tc.tool, result)
			}
			if len(provider.vpnCalls) != 1 || !reflect.DeepEqual(provider.vpnCalls[0], tc.want) {
				t.Fatalf("%s provider calls = %+v, want [%+v]", tc.tool, provider.vpnCalls, tc.want)
			}
		})
	}
}

func TestVPNToolsPropagateProviderFailures(t *testing.T) {
	refusal := errors.New("vpn control plane is not configured")
	provider := &mockServiceProvider{vpnErr: refusal}
	registry := NewToolRegistry(provider, nil)

	for _, tc := range vpnToolCases {
		if _, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args); !errors.Is(err, refusal) {
			t.Fatalf("%s error = %v, want the provider failure", tc.tool, err)
		}
	}
}

func TestDispatchVPNToolIgnoresOtherTools(t *testing.T) {
	registry := NewToolRegistry(&mockServiceProvider{}, nil)

	_, handled, err := registry.dispatchVPNTool(context.Background(), "ntp_status", nil)
	if handled || err != nil {
		t.Fatalf("dispatchVPNTool(ntp_status) handled = %v, err = %v; want unhandled", handled, err)
	}
}

func TestVPNToolPermissionsFollowTheScopeTable(t *testing.T) {
	want := map[string]string{
		"vpn_peer_enrol":            "vpn:write",
		"vpn_peer_list":             "vpn:read",
		"vpn_peer_revoke":           "vpn:write",
		"vpn_status":                "vpn:read",
		"vpn_posture_policy_get":    "vpn:admin",
		"vpn_posture_policy_set":    "vpn:admin",
		"vpn_posture_policy_delete": "vpn:admin",
		"vpn_posture_policy_list":   "vpn:admin",
	}
	permissions := toolPermissionCatalog()
	for tool, scope := range want {
		if permissions[tool] != scope {
			t.Fatalf("permission for %s = %q, want %q", tool, permissions[tool], scope)
		}
	}
}

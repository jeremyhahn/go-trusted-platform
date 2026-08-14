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
)

// gatewayLBToolNames is the canonical tool set of the load balancer.
var gatewayLBToolNames = []string{
	"gateway_lb_vip_add",
	"gateway_lb_vip_remove",
	"gateway_lb_vip_get",
	"gateway_lb_vip_list",
	"gateway_lb_vip_set_backends",
	"gateway_lb_status",
}

// lbAddArgs builds valid gateway_lb_vip_add arguments.
func lbAddArgs() map[string]interface{} {
	return map[string]interface{}{
		"protocol": "tcp",
		"address":  "10.100.0.10",
		"port":     443,
		"backends": []interface{}{
			map[string]interface{}{"address": "10.0.1.5", "port": 8443, "weight": 2},
			map[string]interface{}{"address": "10.0.1.6", "port": 8443},
		},
	}
}

// lbTargetArgs builds valid keyed VIP arguments.
func lbTargetArgs() map[string]interface{} {
	return map[string]interface{}{
		"protocol": "tcp",
		"address":  "10.100.0.10",
		"port":     443,
	}
}

func TestGatewayLBToolRegistrationAndRoutingParity(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	registered := make(map[string]struct{})
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = struct{}{}
	}

	for _, name := range gatewayLBToolNames {
		if _, ok := registered[name]; !ok {
			t.Errorf("tool %s not registered", name)
		}
		if _, ok := gatewayLBToolExecutors[name]; !ok {
			t.Errorf("tool %s has no executor", name)
		}
	}
	if len(gatewayLBToolExecutors) != len(gatewayLBToolNames) {
		t.Errorf("executor map has %d entries, want %d", len(gatewayLBToolExecutors), len(gatewayLBToolNames))
	}
}

func TestGatewayLBToolExecution(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	ctx := context.Background()

	tests := []struct {
		tool string
		args map[string]interface{}
	}{
		{"gateway_lb_vip_add", lbAddArgs()},
		{"gateway_lb_vip_remove", lbTargetArgs()},
		{"gateway_lb_vip_get", lbTargetArgs()},
		{"gateway_lb_vip_list", map[string]interface{}{}},
		{"gateway_lb_vip_set_backends", lbAddArgs()},
		{"gateway_lb_status", map[string]interface{}{}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			result, err := registry.ExecuteTool(ctx, tt.tool, tt.args)
			if err != nil {
				t.Fatalf("ExecuteTool(%s): %v", tt.tool, err)
			}
			if result == nil {
				t.Fatalf("ExecuteTool(%s) returned nil result", tt.tool)
			}
		})
	}
}

func TestGatewayLBToolArgumentErrors(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	ctx := context.Background()

	tests := []struct {
		name    string
		tool    string
		args    map[string]interface{}
		wantErr error
	}{
		{"add missing protocol", "gateway_lb_vip_add", map[string]interface{}{
			"address": "10.100.0.10", "port": 443,
			"backends": []interface{}{map[string]interface{}{"address": "10.0.1.5", "port": 8443}},
		}, ErrLBVIPTargetRequired},
		{"add missing backends", "gateway_lb_vip_add", lbTargetArgs(), ErrLBBackendsRequired},
		{"add bad backend port", "gateway_lb_vip_add", map[string]interface{}{
			"protocol": "tcp", "address": "10.100.0.10", "port": 443,
			"backends": []interface{}{map[string]interface{}{"address": "10.0.1.5", "port": 0}},
		}, ErrLBBackendsRequired},
		{"remove missing port", "gateway_lb_vip_remove", map[string]interface{}{
			"protocol": "tcp", "address": "10.100.0.10",
		}, ErrLBVIPTargetRequired},
		{"get missing address", "gateway_lb_vip_get", map[string]interface{}{
			"protocol": "tcp", "port": 443,
		}, ErrLBVIPTargetRequired},
		{"set-backends port overflow", "gateway_lb_vip_set_backends", map[string]interface{}{
			"protocol": "tcp", "address": "10.100.0.10", "port": 70000,
			"backends": []interface{}{map[string]interface{}{"address": "10.0.1.5", "port": 8443}},
		}, ErrLBVIPTargetRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tt.tool, tt.args)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ExecuteTool = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestGatewayLBToolPermissions(t *testing.T) {
	authz := NewAuthorizationChecker(nil, nil)

	want := map[string]string{
		"gateway_lb_vip_add":          "sdn:write",
		"gateway_lb_vip_remove":       "sdn:delete",
		"gateway_lb_vip_get":          "sdn:read",
		"gateway_lb_vip_list":         "sdn:read",
		"gateway_lb_vip_set_backends": "sdn:write",
		"gateway_lb_status":           "sdn:read",
	}
	for tool, perm := range want {
		if got := authz.toolPermissions[tool]; got != perm {
			t.Errorf("permission(%s) = %q, want %q", tool, got, perm)
		}
	}
}

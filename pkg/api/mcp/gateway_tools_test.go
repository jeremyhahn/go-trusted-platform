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
)

func TestGatewayToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeGatewayStatus success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_status", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewaySnapshot returns the telemetry snapshot", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_snapshot", map[string]interface{}{"gateway_id": "node-01-gateway"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		snapshot, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result is %T, want a decoded object", result)
		}
		if snapshot["gateway_id"] != "node-01-gateway" {
			t.Fatalf("gateway_id = %v, want the requested gateway", snapshot["gateway_id"])
		}
	})

	t.Run("executeGatewaySnapshots lists the fleet", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_snapshots", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		listed, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result is %T, want an object carrying snapshots", result)
		}
		snapshots, ok := listed["snapshots"].([]interface{})
		if !ok || len(snapshots) != 1 {
			t.Fatalf("snapshots = %v, want one entry", listed["snapshots"])
		}
	})

	t.Run("executeGatewayModeSet success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_mode_set", map[string]interface{}{
			"modes": []interface{}{"router", "nat"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewayModeSet missing modes", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_mode_set", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing modes")
		}
		if err != ErrGatewayModesRequired {
			t.Fatalf("expected ErrGatewayModesRequired, got %v", err)
		}
	})

	t.Run("executeGatewayBGPStatus success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_bgp_status", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewayBGPPeers success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_bgp_peers", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["peers"]; !exists {
			t.Fatal("result should contain 'peers' key")
		}
	})

	t.Run("executeGatewayBGPAnnounce success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_bgp_announce", map[string]interface{}{
			"prefix":   "10.0.0.0/24",
			"next_hop": "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeGatewayBGPAnnounce missing prefix", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_bgp_announce", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing prefix")
		}
		if err != ErrBGPPrefixRequired {
			t.Fatalf("expected ErrBGPPrefixRequired, got %v", err)
		}
	})

	t.Run("executeGatewayBGPWithdraw success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_bgp_withdraw", map[string]interface{}{
			"prefix": "10.0.0.0/24",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeGatewayBGPWithdraw missing prefix", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_bgp_withdraw", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing prefix")
		}
		if err != ErrBGPPrefixRequired {
			t.Fatalf("expected ErrBGPPrefixRequired, got %v", err)
		}
	})

	t.Run("executeGatewayBGPPrefixes success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_bgp_prefixes", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["prefixes"]; !exists {
			t.Fatal("result should contain 'prefixes' key")
		}
	})

	t.Run("executeGatewayIPAMPools success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_pools", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["pools"]; !exists {
			t.Fatal("result should contain 'pools' key")
		}
	})

	t.Run("executeGatewayIPAMPoolCreate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_create", map[string]interface{}{
			"name":    "test-pool",
			"cidr":    "10.0.0.0/24",
			"gateway": "10.0.0.1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewayIPAMPoolCreate missing name", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_create", map[string]interface{}{
			"cidr": "10.0.0.0/24",
		})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
		if err != ErrIPAMPoolNameRequired {
			t.Fatalf("expected ErrIPAMPoolNameRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMPoolCreate missing cidr", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_create", map[string]interface{}{
			"name": "test-pool",
		})
		if err == nil {
			t.Fatal("expected error for missing cidr")
		}
		if err != ErrIPAMPoolCIDRRequired {
			t.Fatalf("expected ErrIPAMPoolCIDRRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMPoolDelete success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_delete", map[string]interface{}{
			"pool_id": "pool-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeGatewayIPAMPoolDelete missing pool_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_delete", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing pool_id")
		}
		if err != ErrIPAMPoolIDRequired {
			t.Fatalf("expected ErrIPAMPoolIDRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMAllocate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_allocate", map[string]interface{}{
			"pool_id":   "pool-123",
			"device_id": "device-456",
			"hostname":  "node-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewayIPAMAllocate missing pool_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_allocate", map[string]interface{}{
			"device_id": "device-456",
		})
		if err == nil {
			t.Fatal("expected error for missing pool_id")
		}
		if err != ErrIPAMPoolIDRequired {
			t.Fatalf("expected ErrIPAMPoolIDRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMAllocate missing device_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_allocate", map[string]interface{}{
			"pool_id": "pool-123",
		})
		if err == nil {
			t.Fatal("expected error for missing device_id")
		}
		if err != ErrIPAMDeviceIDRequired {
			t.Fatalf("expected ErrIPAMDeviceIDRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMRelease success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_release", map[string]interface{}{
			"ip": "10.0.0.5",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeGatewayIPAMRelease missing ip", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_release", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing ip")
		}
		if err != ErrIPAMIPRequired {
			t.Fatalf("expected ErrIPAMIPRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMAllocations success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_allocations", map[string]interface{}{
			"pool_id": "pool-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["allocations"]; !exists {
			t.Fatal("result should contain 'allocations' key")
		}
	})
}

// TestGatewayStatusModePermissions pins the catalog entries for the status
// and mode tools; a tool without an entry is refused by authz (#65).
func TestGatewayStatusModePermissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	cases := map[string]string{
		"gateway_status":   "sdn:read",
		"gateway_mode_set": "sdn:write",
	}
	for tool, want := range cases {
		if got := checker.toolPermissions[tool]; got != want {
			t.Errorf("permission for %s = %q, want %q", tool, got, want)
		}
	}
}

func TestGatewayIPAMPoolCRUD(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeGatewayIPAMPools with zone filter", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_pools", map[string]interface{}{
			"zone": "control-plane",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["pools"]; !exists {
			t.Fatal("result should contain 'pools' key")
		}
	})

	t.Run("executeGatewayIPAMPoolGet success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_get", map[string]interface{}{
			"pool_id": "pool-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewayIPAMPoolGet missing pool_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_get", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing pool_id")
		}
		if err != ErrIPAMPoolIDRequired {
			t.Fatalf("expected ErrIPAMPoolIDRequired, got %v", err)
		}
	})

	t.Run("executeGatewayIPAMPoolUpdate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_update", map[string]interface{}{
			"pool_id": "pool-123",
			"name":    "updated-pool",
			"zone":    "provisioning",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeGatewayIPAMPoolUpdate missing pool_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_update", map[string]interface{}{
			"name": "updated-pool",
		})
		if err == nil {
			t.Fatal("expected error for missing pool_id")
		}
		if err != ErrIPAMPoolIDRequired {
			t.Fatalf("expected ErrIPAMPoolIDRequired, got %v", err)
		}
	})
}

func TestGatewayErrorTypes(t *testing.T) {
	t.Run("GatewayError format", func(t *testing.T) {
		err := &GatewayError{Code: "TEST_CODE", Message: "test message"}
		expected := "TEST_CODE: test message"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

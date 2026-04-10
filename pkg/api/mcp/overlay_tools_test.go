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

func TestOverlayToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeOverlayStatus success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_status", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeOverlayVTEPList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_vtep_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["vteps"]; !exists {
			t.Fatal("result should contain 'vteps' key")
		}
	})

	t.Run("executeOverlayVTEPGet success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_vtep_get", map[string]interface{}{
			"node_id": "node-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeOverlayVTEPGet missing node_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "overlay_vtep_get", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing node_id")
		}
		if err != ErrOverlayNodeIDRequired {
			t.Fatalf("expected ErrOverlayNodeIDRequired, got %v", err)
		}
	})

	t.Run("executeOverlayVNIList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_vni_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["vnis"]; !exists {
			t.Fatal("result should contain 'vnis' key")
		}
	})

	t.Run("executeOverlayVNICreate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_vni_create", map[string]interface{}{
			"vni":  float64(100),
			"vlan": float64(200),
			"name": "test-vni",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeOverlayVNICreate missing vni", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "overlay_vni_create", map[string]interface{}{
			"name": "test-vni",
		})
		if err == nil {
			t.Fatal("expected error for missing vni")
		}
		if err != ErrOverlayVNIRequired {
			t.Fatalf("expected ErrOverlayVNIRequired, got %v", err)
		}
	})

	t.Run("executeOverlayVNIDelete success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_vni_delete", map[string]interface{}{
			"vni": float64(100),
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

	t.Run("executeOverlayVNIDelete missing vni", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "overlay_vni_delete", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing vni")
		}
		if err != ErrOverlayVNIRequired {
			t.Fatalf("expected ErrOverlayVNIRequired, got %v", err)
		}
	})

	t.Run("executeOverlayTunnelList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_tunnel_list", map[string]interface{}{
			"vni": float64(100),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["tunnels"]; !exists {
			t.Fatal("result should contain 'tunnels' key")
		}
	})

	t.Run("executeOverlayMACList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_mac_list", map[string]interface{}{
			"vni": float64(100),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["macs"]; !exists {
			t.Fatal("result should contain 'macs' key")
		}
	})

	t.Run("executeOverlayMACForget success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "overlay_mac_forget", map[string]interface{}{
			"mac": "aa:bb:cc:dd:ee:ff",
			"vni": float64(100),
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

	t.Run("executeOverlayMACForget missing mac", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "overlay_mac_forget", map[string]interface{}{
			"vni": float64(100),
		})
		if err == nil {
			t.Fatal("expected error for missing mac")
		}
		if err != ErrOverlayMACRequired {
			t.Fatalf("expected ErrOverlayMACRequired, got %v", err)
		}
	})

	t.Run("executeOverlayMACForget missing vni", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "overlay_mac_forget", map[string]interface{}{
			"mac": "aa:bb:cc:dd:ee:ff",
		})
		if err == nil {
			t.Fatal("expected error for missing vni")
		}
		if err != ErrOverlayVNIRequired {
			t.Fatalf("expected ErrOverlayVNIRequired, got %v", err)
		}
	})
}

func TestOverlayErrorTypes(t *testing.T) {
	t.Run("OverlayError format", func(t *testing.T) {
		err := &OverlayError{Code: "TEST_CODE", Message: "test message"}
		expected := "TEST_CODE: test message"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

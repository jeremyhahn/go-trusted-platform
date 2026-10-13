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

func TestNewToolRegistry(t *testing.T) {
	t.Run("creates registry with service and logger", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()

		registry := NewToolRegistry(svc, log)

		if registry == nil {
			t.Fatal("NewToolRegistry returned nil")
		}
		if registry.service == nil {
			t.Error("service should not be nil")
		}
		if registry.logger == nil {
			t.Error("logger should not be nil")
		}
	})

	t.Run("registers tools on creation", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()

		registry := NewToolRegistry(svc, log)

		tools := registry.ListTools()
		if len(tools) == 0 {
			t.Error("tools should not be empty")
		}
	})

	t.Run("has no auth checker by default", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()

		registry := NewToolRegistry(svc, log)

		if registry.authChecker != nil {
			t.Error("authChecker should be nil by default")
		}
	})
}

func TestToolRegistry_ListTools(t *testing.T) {
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("returns all registered tools", func(t *testing.T) {
		tools := registry.ListTools()

		// Check for expected tool categories
		expectedTools := []string{
			// vTPM
			"vtpm_create", "vtpm_delete", "vtpm_list", "vtpm_start", "vtpm_stop",
			"vtpm_quote", "vtpm_seal", "vtpm_unseal", "vtpm_extend_pcr", "vtpm_read_pcr",
			// DNS
			"dns_add_record", "dns_delete_record", "dns_get_record", "dns_list_records",
			"dns_resolve", "dns_create_zone", "dns_delete_zone", "dns_list_zones",
			// Device
			"device_register", "device_get", "device_list", "device_delete",
			"device_update", "device_attest", "device_record_attest_cert", "device_provision",
			// SDN
			"sdn_get_port_state", "sdn_set_port_state", "sdn_list_bridges",
			"sdn_create_bridge", "sdn_delete_bridge", "sdn_add_port", "sdn_delete_port",
			"sdn_apply_policy", "sdn_get_policy", "sdn_list_policies",
			// Health
			"platform_health", "platform_liveness", "platform_readiness",
		}

		toolMap := make(map[string]bool)
		for _, tool := range tools {
			toolMap[tool.Name] = true
		}

		for _, expected := range expectedTools {
			if !toolMap[expected] {
				t.Errorf("expected tool %s not found", expected)
			}
		}
	})

	t.Run("tools have required fields", func(t *testing.T) {
		tools := registry.ListTools()

		for _, tool := range tools {
			if tool.Name == "" {
				t.Error("tool has empty name")
			}
			if tool.Description == "" {
				t.Errorf("tool %s has empty description", tool.Name)
			}
			if tool.InputSchema == nil {
				t.Errorf("tool %s has nil InputSchema", tool.Name)
			}
		}
	})

	t.Run("tool schemas have type property", func(t *testing.T) {
		tools := registry.ListTools()

		for _, tool := range tools {
			schemaType, ok := tool.InputSchema["type"]
			if !ok {
				t.Errorf("tool %s schema missing 'type' property", tool.Name)
				continue
			}
			if schemaType != "object" {
				t.Errorf("tool %s schema type = %v, want object", tool.Name, schemaType)
			}
		}
	})
}

func TestToolRegistry_SetAuthorizationChecker(t *testing.T) {
	t.Run("sets auth checker", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewToolRegistry(svc, log)

		checker := NewAuthorizationChecker(nil, nil)
		registry.SetAuthorizationChecker(checker)

		if registry.authChecker != checker {
			t.Error("authChecker was not set correctly")
		}
	})

	t.Run("can set nil auth checker", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewToolRegistry(svc, log)

		// First set a checker
		checker := NewAuthorizationChecker(nil, nil)
		registry.SetAuthorizationChecker(checker)

		// Then clear it
		registry.SetAuthorizationChecker(nil)

		if registry.authChecker != nil {
			t.Error("authChecker should be nil after clearing")
		}
	})
}

func TestToolRegistry_ExecuteTool(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for unknown tool", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "unknown_tool", nil)
		if err == nil {
			t.Error("expected error for unknown tool")
		}
	})

	t.Run("adds timeout to context if not present", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewToolRegistry(svc, log)

		// This should not hang or error due to timeout handling
		result, err := registry.ExecuteTool(ctx, "platform_health", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestToolRegistry_VTPMTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("vtpm_create success", func(t *testing.T) {
		args := map[string]interface{}{
			"name":      "test-vtpm",
			"algorithm": "RSA",
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_create", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("vtpm_create with default algorithm", func(t *testing.T) {
		args := map[string]interface{}{
			"name": "test-vtpm",
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_create", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("vtpm_create error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmCreateFunc = func(ctx context.Context, name, algorithm string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_create", map[string]interface{}{"name": "test"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("vtpm_delete success", func(t *testing.T) {
		args := map[string]interface{}{
			"name": "test-vtpm",
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_delete", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("vtpm_list success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "vtpm_list", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["instances"]; !ok {
			t.Error("expected 'instances' key in result")
		}
	})

	t.Run("vtpm_start success", func(t *testing.T) {
		args := map[string]interface{}{"name": "test-vtpm"}

		result, err := registry.ExecuteTool(ctx, "vtpm_start", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("vtpm_stop success", func(t *testing.T) {
		args := map[string]interface{}{"name": "test-vtpm"}

		result, err := registry.ExecuteTool(ctx, "vtpm_stop", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})
}

func TestToolRegistry_DNSTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("dns_add_record success", func(t *testing.T) {
		args := map[string]interface{}{
			"name":        "host.example.com",
			"record_type": "A",
			"value":       "192.168.1.1",
			"ttl":         300,
		}

		result, err := registry.ExecuteTool(ctx, "dns_add_record", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("dns_add_record with default ttl", func(t *testing.T) {
		args := map[string]interface{}{
			"name":        "host.example.com",
			"record_type": "A",
			"value":       "192.168.1.1",
		}

		result, err := registry.ExecuteTool(ctx, "dns_add_record", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("dns_delete_record success", func(t *testing.T) {
		args := map[string]interface{}{
			"name":        "host.example.com",
			"record_type": "A",
		}

		result, err := registry.ExecuteTool(ctx, "dns_delete_record", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("dns_get_record success", func(t *testing.T) {
		args := map[string]interface{}{
			"name":        "host.example.com",
			"record_type": "A",
		}

		result, err := registry.ExecuteTool(ctx, "dns_get_record", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("dns_list_records success", func(t *testing.T) {
		args := map[string]interface{}{
			"zone": "example.com",
		}

		result, err := registry.ExecuteTool(ctx, "dns_list_records", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["records"]; !ok {
			t.Error("expected 'records' key in result")
		}
	})

	t.Run("dns_resolve success with default type", func(t *testing.T) {
		args := map[string]interface{}{
			"name": "host.example.com",
		}

		result, err := registry.ExecuteTool(ctx, "dns_resolve", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["results"]; !ok {
			t.Error("expected 'results' key in result")
		}
	})

	t.Run("dns_create_zone success", func(t *testing.T) {
		args := map[string]interface{}{
			"zone": "newzone.com",
		}

		result, err := registry.ExecuteTool(ctx, "dns_create_zone", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("dns_delete_zone success", func(t *testing.T) {
		args := map[string]interface{}{
			"zone": "oldzone.com",
		}

		result, err := registry.ExecuteTool(ctx, "dns_delete_zone", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("dns_list_zones success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "dns_list_zones", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["zones"]; !ok {
			t.Error("expected 'zones' key in result")
		}
	})
}

func TestToolRegistry_DeviceTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("device_register success", func(t *testing.T) {
		args := map[string]interface{}{
			"serial": "SN-533",
			"model":  "model-533",
		}

		result, err := registry.ExecuteTool(ctx, "device_register", args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result is %T, want a map", result)
		}
		if resultMap["serial"] != "SN-533" || resultMap["model"] != "model-533" {
			t.Errorf("result = %v, want serial SN-533 and model model-533", resultMap)
		}
	})

	t.Run("device_register without serial", func(t *testing.T) {
		args := map[string]interface{}{"model": "model-533"}

		_, err := registry.ExecuteTool(ctx, "device_register", args)
		if !errors.Is(err, ErrDeviceSerialRequired) {
			t.Errorf("err = %v, want ErrDeviceSerialRequired", err)
		}
	})

	t.Run("device_get success", func(t *testing.T) {
		args := map[string]interface{}{
			"device_id": "device-123",
		}

		result, err := registry.ExecuteTool(ctx, "device_get", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("device_list success", func(t *testing.T) {
		args := map[string]interface{}{
			"device_type": "iot",
			"status":      "active",
		}

		result, err := registry.ExecuteTool(ctx, "device_list", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["devices"]; !ok {
			t.Error("expected 'devices' key in result")
		}
	})

	t.Run("device_delete success", func(t *testing.T) {
		args := map[string]interface{}{
			"device_id": "device-123",
		}

		result, err := registry.ExecuteTool(ctx, "device_delete", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("device_update success", func(t *testing.T) {
		args := map[string]interface{}{
			"device_id": "device-123",
			"model":     "model-updated",
		}

		result, err := registry.ExecuteTool(ctx, "device_update", args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if resultMap["id"] != "device-123" {
			t.Errorf("result = %v, want the stored device-123", resultMap)
		}
	})

	t.Run("device_attest success", func(t *testing.T) {
		args := map[string]interface{}{
			"device_id": "device-123",
			"evidence":  "ZXZpZGVuY2U=", // base64 "evidence"
		}

		result, err := registry.ExecuteTool(ctx, "device_attest", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("device_attest with invalid base64", func(t *testing.T) {
		args := map[string]interface{}{
			"device_id": "device-123",
			"evidence":  "not-valid!!!",
		}

		_, err := registry.ExecuteTool(ctx, "device_attest", args)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("device_provision success", func(t *testing.T) {
		args := map[string]interface{}{
			"device_id": "device-123",
			"profile":   "default",
		}

		result, err := registry.ExecuteTool(ctx, "device_provision", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})
}

func TestToolRegistry_SDNTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("sdn_get_port_state success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_get_port_state", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("sdn_set_port_state success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
			"state":       "up",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_set_port_state", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_list_bridges success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "sdn_list_bridges", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["bridges"]; !ok {
			t.Error("expected 'bridges' key in result")
		}
	})

	t.Run("sdn_create_bridge success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br-new",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_create_bridge", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_delete_bridge success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br-old",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_delete_bridge", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_add_port success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth1",
			"port_type":   "internal",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_add_port", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_delete_port success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth1",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_delete_port", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_apply_policy success", func(t *testing.T) {
		args := map[string]interface{}{
			"policy_id":   "policy-1",
			"bridge_name": "br0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_apply_policy", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_get_policy success", func(t *testing.T) {
		args := map[string]interface{}{
			"policy_id": "policy-1",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_get_policy", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("sdn_list_policies success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "sdn_list_policies", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["policies"]; !ok {
			t.Error("expected 'policies' key in result")
		}
	})
}

func TestToolRegistry_SDNFlowTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("sdn_add_flow success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"flow": map[string]interface{}{
				"priority": 100,
				"match":    map[string]interface{}{"in_port": 1},
				"actions":  []string{"output:2"},
			},
		}

		result, err := registry.ExecuteTool(ctx, "sdn_add_flow", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_delete_flow success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"flow_id":     "flow-1",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_delete_flow", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_list_flows success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_list_flows", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["flows"]; !ok {
			t.Error("expected 'flows' key in result")
		}
	})

	t.Run("sdn_flush_flows success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_flush_flows", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})
}

func TestToolRegistry_SDNVLANTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("sdn_create_vlan success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"vlan_id":     100,
			"name":        "vlan-100",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_create_vlan", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_delete_vlan success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"vlan_id":     100,
		}

		result, err := registry.ExecuteTool(ctx, "sdn_delete_vlan", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_list_vlans success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_list_vlans", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["vlans"]; !ok {
			t.Error("expected 'vlans' key in result")
		}
	})
}

func TestToolRegistry_SDNPortAuthTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("sdn_authenticate_port success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
			"credentials": map[string]interface{}{
				"username": "user",
				"password": "pass",
			},
		}

		result, err := registry.ExecuteTool(ctx, "sdn_authenticate_port", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("sdn_revoke_port_auth success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_revoke_port_auth", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})
}

func TestToolRegistry_SDNStatsTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("sdn_get_port_stats success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_get_port_stats", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("sdn_get_flow_stats success", func(t *testing.T) {
		args := map[string]interface{}{
			"bridge_name": "br0",
		}

		result, err := registry.ExecuteTool(ctx, "sdn_get_flow_stats", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestToolRegistry_HealthTools(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewToolRegistry(svc, log)

	t.Run("platform_health success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "platform_health", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("platform_liveness success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "platform_liveness", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("platform_readiness success", func(t *testing.T) {
		result, err := registry.ExecuteTool(ctx, "platform_readiness", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getString returns string value", func(t *testing.T) {
		args := map[string]interface{}{"key": "value"}
		result := getString(args, "key")
		if result != "value" {
			t.Errorf("getString() = %s, want value", result)
		}
	})

	t.Run("getString returns empty for missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getString(args, "key")
		if result != "" {
			t.Errorf("getString() = %s, want empty string", result)
		}
	})

	t.Run("getString returns empty for non-string", func(t *testing.T) {
		args := map[string]interface{}{"key": 123}
		result := getString(args, "key")
		if result != "" {
			t.Errorf("getString() = %s, want empty string", result)
		}
	})

	t.Run("getInt returns int from float64", func(t *testing.T) {
		args := map[string]interface{}{"key": float64(42)}
		result := getInt(args, "key")
		if result != 42 {
			t.Errorf("getInt() = %d, want 42", result)
		}
	})

	t.Run("getInt returns int from int", func(t *testing.T) {
		args := map[string]interface{}{"key": 42}
		result := getInt(args, "key")
		if result != 42 {
			t.Errorf("getInt() = %d, want 42", result)
		}
	})

	t.Run("getInt returns int from int64", func(t *testing.T) {
		args := map[string]interface{}{"key": int64(42)}
		result := getInt(args, "key")
		if result != 42 {
			t.Errorf("getInt() = %d, want 42", result)
		}
	})

	t.Run("getInt returns 0 for missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getInt(args, "key")
		if result != 0 {
			t.Errorf("getInt() = %d, want 0", result)
		}
	})

	t.Run("getIntSlice returns slice from interface slice", func(t *testing.T) {
		args := map[string]interface{}{
			"key": []interface{}{float64(1), float64(2), float64(3)},
		}
		result := getIntSlice(args, "key")
		if len(result) != 3 || result[0] != 1 || result[1] != 2 || result[2] != 3 {
			t.Errorf("getIntSlice() = %v, want [1, 2, 3]", result)
		}
	})

	t.Run("getIntSlice returns nil for missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getIntSlice(args, "key")
		if result != nil {
			t.Errorf("getIntSlice() = %v, want nil", result)
		}
	})

	t.Run("getMap returns map value", func(t *testing.T) {
		inner := map[string]interface{}{"nested": "value"}
		args := map[string]interface{}{"key": inner}
		result := getMap(args, "key")
		if result == nil || result["nested"] != "value" {
			t.Errorf("getMap() = %v, unexpected result", result)
		}
	})

	t.Run("getMap returns nil for missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getMap(args, "key")
		if result != nil {
			t.Errorf("getMap() = %v, want nil", result)
		}
	})

	t.Run("getStringMap returns string map", func(t *testing.T) {
		args := map[string]interface{}{
			"key": map[string]interface{}{
				"a": "1",
				"b": "2",
			},
		}
		result := getStringMap(args, "key")
		if result == nil || result["a"] != "1" || result["b"] != "2" {
			t.Errorf("getStringMap() = %v, unexpected result", result)
		}
	})

	t.Run("getStringMap skips non-string values", func(t *testing.T) {
		args := map[string]interface{}{
			"key": map[string]interface{}{
				"a": "1",
				"b": 2,
			},
		}
		result := getStringMap(args, "key")
		if result == nil || result["a"] != "1" {
			t.Errorf("getStringMap() = %v, unexpected result", result)
		}
		if _, ok := result["b"]; ok {
			t.Error("getStringMap should skip non-string values")
		}
	})

	t.Run("getStringMap returns nil for missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getStringMap(args, "key")
		if result != nil {
			t.Errorf("getStringMap() = %v, want nil", result)
		}
	})
}

func TestMarshalResult(t *testing.T) {
	t.Run("marshals struct to interface", func(t *testing.T) {
		input := struct {
			Name string `json:"name"`
		}{Name: "test"}

		result, err := marshalResult(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if resultMap["name"] != "test" {
			t.Errorf("name = %v, want test", resultMap["name"])
		}
	})

	t.Run("marshals slice to interface", func(t *testing.T) {
		input := []string{"a", "b", "c"}

		result, err := marshalResult(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		resultSlice, ok := result.([]interface{})
		if !ok {
			t.Fatal("result is not a slice")
		}
		if len(resultSlice) != 3 {
			t.Errorf("len = %d, want 3", len(resultSlice))
		}
	})

	t.Run("handles nil input", func(t *testing.T) {
		result, err := marshalResult(nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("result = %v, want nil", result)
		}
	})
}

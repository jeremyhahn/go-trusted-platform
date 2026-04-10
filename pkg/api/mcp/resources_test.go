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

func TestNewResourceRegistry(t *testing.T) {
	t.Run("creates registry with service and logger", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()

		registry := NewResourceRegistry(svc, log)

		if registry == nil {
			t.Fatal("NewResourceRegistry returned nil")
		}
		if registry.service == nil {
			t.Error("service should not be nil")
		}
		if registry.logger == nil {
			t.Error("logger should not be nil")
		}
	})

	t.Run("registers resources on creation", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()

		registry := NewResourceRegistry(svc, log)

		resources := registry.ListResources()
		if len(resources) == 0 {
			t.Error("resources should not be empty")
		}
	})
}

func TestResourceRegistry_ListResources(t *testing.T) {
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewResourceRegistry(svc, log)

	t.Run("returns all registered resources", func(t *testing.T) {
		resources := registry.ListResources()

		expectedURIs := []string{
			"platform://vtpm/list",
			"platform://vtpm/{name}",
			"platform://dns/zones",
			"platform://dns/zone/{zone}",
			"platform://device/list",
			"platform://device/{id}",
			"platform://sdn/bridges",
			"platform://sdn/policies",
			"platform://health",
			"platform://status",
		}

		uriMap := make(map[string]bool)
		for _, resource := range resources {
			uriMap[resource.URI] = true
		}

		for _, expected := range expectedURIs {
			if !uriMap[expected] {
				t.Errorf("expected resource %s not found", expected)
			}
		}
	})

	t.Run("resources have required fields", func(t *testing.T) {
		resources := registry.ListResources()

		for _, resource := range resources {
			if resource.URI == "" {
				t.Error("resource has empty URI")
			}
			if resource.Name == "" {
				t.Errorf("resource %s has empty name", resource.URI)
			}
			if resource.Description == "" {
				t.Errorf("resource %s has empty description", resource.URI)
			}
		}
	})

	t.Run("resources have mime type", func(t *testing.T) {
		resources := registry.ListResources()

		for _, resource := range resources {
			if resource.MimeType != "application/json" {
				t.Errorf("resource %s has unexpected mime type: %s", resource.URI, resource.MimeType)
			}
		}
	})
}

func TestResourceRegistry_ReadResource(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects invalid URI prefix", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "http://example.com/resource")
		if err == nil {
			t.Error("expected error for invalid URI prefix")
		}
	})

	t.Run("rejects empty path", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://")
		if err == nil {
			t.Error("expected error for empty path")
		}
	})

	t.Run("rejects unknown resource type", func(t *testing.T) {
		svc := newMockServiceProvider()
		log := newTestLogger()
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://unknown/resource")
		if err == nil {
			t.Error("expected error for unknown resource type")
		}
	})
}

func TestResourceRegistry_ReadVTPMResource(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("reads vtpm list", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://vtpm/list")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["contents"]; !ok {
			t.Error("expected 'contents' key in result")
		}
	})

	t.Run("reads vtpm list with empty path", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://vtpm")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads specific vtpm", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://vtpm/my-vtpm")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if resultMap["name"] != "my-vtpm" {
			t.Errorf("name = %v, want my-vtpm", resultMap["name"])
		}
	})

	t.Run("handles vtpm list error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmListFunc = func(ctx context.Context) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://vtpm/list")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestResourceRegistry_ReadDNSResource(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("reads dns zones", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://dns/zones")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads dns zones with empty path", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://dns")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads dns zone records", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://dns/zone/example.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("rejects invalid dns path", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://dns/invalid")
		if err == nil {
			t.Error("expected error for invalid dns path")
		}
	})

	t.Run("rejects zone without zone name", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://dns/zone")
		if err == nil {
			t.Error("expected error for zone without name")
		}
	})

	t.Run("handles dns list zones error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsListZonesFunc = func(ctx context.Context) ([]string, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://dns/zones")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("handles dns list records error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsListRecordsFunc = func(ctx context.Context, zone string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://dns/zone/example.com")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestResourceRegistry_ReadDeviceResource(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("reads device list", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://device/list")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads device list with empty path", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://device")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads specific device", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://device/device-123")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("handles device list error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceListFunc = func(ctx context.Context, filter map[string]string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://device/list")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("handles device get error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceGetFunc = func(ctx context.Context, deviceID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://device/device-123")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestResourceRegistry_ReadSDNResource(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("reads sdn bridges", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://sdn/bridges")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads sdn bridges with empty path", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://sdn")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("reads sdn policies", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://sdn/policies")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("rejects invalid sdn path", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://sdn/invalid")
		if err == nil {
			t.Error("expected error for invalid sdn path")
		}
	})

	t.Run("handles sdn list bridges error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnListBridgesFunc = func(ctx context.Context) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://sdn/bridges")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("handles sdn list policies error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnListPoliciesFunc = func(ctx context.Context) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://sdn/policies")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestResourceRegistry_ReadHealthResource(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("reads health resource", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://health")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("handles health error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.healthFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		_, err := registry.ReadResource(ctx, "platform://health")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestResourceRegistry_ReadStatusResource(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("reads status resource", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.ReadResource(ctx, "platform://status")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["contents"]; !ok {
			t.Error("expected 'contents' key in result")
		}
	})

	t.Run("status continues on individual service errors", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.healthFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		svc.vtpmListFunc = func(ctx context.Context) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewResourceRegistry(svc, log)

		// Should still succeed, just with missing data
		result, err := registry.ReadResource(ctx, "platform://status")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestResourceRegistry_FormatResourceContent(t *testing.T) {
	log := newTestLogger()

	t.Run("formats map data", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		data := map[string]interface{}{"key": "value"}
		result, err := registry.formatResourceContent(data)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		contents, ok := resultMap["contents"].([]map[string]interface{})
		if !ok {
			t.Fatal("contents is not a slice of maps")
		}

		if len(contents) != 1 {
			t.Errorf("expected 1 content item, got %d", len(contents))
		}

		if contents[0]["mimeType"] != "application/json" {
			t.Errorf("mimeType = %v, want application/json", contents[0]["mimeType"])
		}
	})

	t.Run("formats slice data", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		data := []string{"a", "b", "c"}
		result, err := registry.formatResourceContent(data)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		contents, ok := resultMap["contents"].([]map[string]interface{})
		if !ok {
			t.Fatal("contents is not a slice of maps")
		}

		if contents[0]["text"] == "" {
			t.Error("text should not be empty")
		}
	})

	t.Run("handles nil data", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewResourceRegistry(svc, log)

		result, err := registry.formatResourceContent(nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		contents, ok := resultMap["contents"].([]map[string]interface{})
		if !ok {
			t.Fatal("contents is not a slice of maps")
		}

		if contents[0]["text"] != "null" {
			t.Errorf("text = %v, want null", contents[0]["text"])
		}
	})
}

func TestResourceRegistry_FormatResourceContent_MarshalError(t *testing.T) {
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewResourceRegistry(svc, log)

	// Channels cannot be marshaled to JSON
	type unmarshalable struct {
		Ch chan int
	}

	data := unmarshalable{Ch: make(chan int)}
	_, err := registry.formatResourceContent(data)
	if err == nil {
		t.Error("expected error when marshaling unmarshalable data")
	}
}

func TestResourceRegistry_ReadResource_UnknownResource(t *testing.T) {
	svc := newMockServiceProvider()
	log := newTestLogger()
	registry := NewResourceRegistry(svc, log)
	ctx := context.Background()

	_, err := registry.ReadResource(ctx, "unknown-resource://test")
	if err == nil {
		t.Error("expected error for unknown resource URI")
	}
}

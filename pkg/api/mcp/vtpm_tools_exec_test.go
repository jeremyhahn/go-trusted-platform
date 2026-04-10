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
	"encoding/base64"
	"testing"
)

func TestVTPMExtendedToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeVTPMGet success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_get", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMGet service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmGetFunc = func(ctx context.Context, name string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_get", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeVTPMValidate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_validate", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMExport success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_export", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMImport success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_import", map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString([]byte("bundle-data")),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMImport invalid base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_import", map[string]interface{}{
			"data": "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
		if err != ErrVTPMInvalidData {
			t.Fatalf("expected ErrVTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeVTPMTemplateCreate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_template_create", map[string]interface{}{
			"id":          "tmpl-1",
			"description": "Test template",
			"algorithm":   "ECC",
			"secure_boot": true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMTemplateCreate default algorithm", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmCreateTemplateFunc = func(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error) {
			if algorithm != "RSA" {
				t.Errorf("expected default algorithm RSA, got %s", algorithm)
			}
			return map[string]interface{}{"id": id}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_template_create", map[string]interface{}{
			"id":          "tmpl-1",
			"description": "Test template",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeVTPMTemplateGet success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_template_get", map[string]interface{}{
			"id": "tmpl-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMTemplateDelete success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_template_delete", map[string]interface{}{
			"id": "tmpl-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["deleted"] != true {
			t.Fatal("expected deleted=true")
		}
	})

	t.Run("executeVTPMTemplateList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_template_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMTemplateClone success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_template_clone", map[string]interface{}{
			"template_id": "tmpl-1",
			"hostname":    "node-42",
			"labels":      map[string]interface{}{"env": "prod"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMGetBundlePath success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_get_bundle_path", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMGetTPMSocketPath success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_get_tpm_socket_path", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMGetNVRAMPath success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_get_nvram_path", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeVTPMIsRunning success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_is_running", map[string]interface{}{
			"name": "test-vtpm",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})
}

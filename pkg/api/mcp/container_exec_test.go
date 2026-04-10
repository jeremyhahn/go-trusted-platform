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

func TestContainerCreateExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("full config options", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.containerCreateFunc = func(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
			if name != "test-container" {
				t.Errorf("expected name 'test-container', got %s", name)
			}
			if image != "alpine:latest" {
				t.Errorf("expected image 'alpine:latest', got %s", image)
			}
			// Verify config contains all optional fields
			if _, ok := config["command"]; !ok {
				t.Error("expected 'command' in config")
			}
			if _, ok := config["args"]; !ok {
				t.Error("expected 'args' in config")
			}
			if _, ok := config["env"]; !ok {
				t.Error("expected 'env' in config")
			}
			if _, ok := config["labels"]; !ok {
				t.Error("expected 'labels' in config")
			}
			if _, ok := config["working_dir"]; !ok {
				t.Error("expected 'working_dir' in config")
			}
			if _, ok := config["user"]; !ok {
				t.Error("expected 'user' in config")
			}
			if _, ok := config["privileged"]; !ok {
				t.Error("expected 'privileged' in config")
			}
			if _, ok := config["mounts"]; !ok {
				t.Error("expected 'mounts' in config")
			}
			if _, ok := config["ports"]; !ok {
				t.Error("expected 'ports' in config")
			}
			if _, ok := config["resources"]; !ok {
				t.Error("expected 'resources' in config")
			}
			return map[string]interface{}{"id": "container-123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":        "test-container",
			"image":       "alpine:latest",
			"command":     []interface{}{"/bin/sh"},
			"args":        []interface{}{"-c", "echo hello"},
			"env":         map[string]interface{}{"FOO": "bar"},
			"labels":      map[string]interface{}{"app": "test"},
			"working_dir": "/app",
			"user":        "nobody",
			"privileged":  true,
			"mounts":      []interface{}{map[string]interface{}{"source": "/host", "target": "/container"}},
			"ports":       []interface{}{map[string]interface{}{"container_port": float64(8080)}},
			"resources":   map[string]interface{}{"cpu_limit": "2"},
		}

		result, err := registry.ExecuteTool(ctx, "container_create", args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("container create service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.containerCreateFunc = func(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "container_create", map[string]interface{}{
			"name":  "test",
			"image": "alpine",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("container list with filters", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.containerListFunc = func(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
			if !all {
				t.Error("expected all=true")
			}
			if limit != 25 {
				t.Errorf("expected limit=25, got %d", limit)
			}
			if val, ok := filters["status"]; !ok || len(val) != 1 || val[0] != "running" {
				t.Errorf("expected status filter ['running'], got %v", filters["status"])
			}
			if val, ok := filters["labels"]; !ok || len(val) != 2 {
				t.Errorf("expected labels filter with 2 items, got %v", filters["labels"])
			}
			return []interface{}{}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "container_list", map[string]interface{}{
			"all":   true,
			"limit": float64(25),
			"filters": map[string]interface{}{
				"status": "running",
				"labels": []interface{}{"app=test", "env=prod"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("container list service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.containerListFunc = func(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "container_list", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("container start service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.containerStartFunc = func(ctx context.Context, id string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "container_start", map[string]interface{}{
			"id": "container-123",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

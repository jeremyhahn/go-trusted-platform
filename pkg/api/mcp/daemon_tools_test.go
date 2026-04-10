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

func TestDaemonToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeDaemonStatus success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_status", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonStatus service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonStatusFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_status", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeDaemonVersion success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_version", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonVersion service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonVersionFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_version", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeDaemonListServices success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_list_services", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonListServices service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonListServicesFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_list_services", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeDaemonGetService success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_get_service", map[string]interface{}{
			"name": "ca",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonGetService missing name", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_get_service", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
		if _, ok := err.(ErrDaemonServiceNameRequired); !ok {
			t.Fatalf("expected ErrDaemonServiceNameRequired, got %T: %v", err, err)
		}
	})

	t.Run("executeDaemonGetService service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonGetServiceFunc = func(ctx context.Context, name string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_get_service", map[string]interface{}{
			"name": "ca",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeDaemonStartService success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_start_service", map[string]interface{}{
			"name": "ca",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonStartService missing name", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_start_service", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
	})

	t.Run("executeDaemonStartService service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonStartServiceFunc = func(ctx context.Context, name string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_start_service", map[string]interface{}{
			"name": "ca",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeDaemonStopService success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_stop_service", map[string]interface{}{
			"name": "ca",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonStopService missing name", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_stop_service", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
	})

	t.Run("executeDaemonRestartService success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_restart_service", map[string]interface{}{
			"name": "ca",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonRestartService missing name", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_restart_service", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing name")
		}
	})

	t.Run("executeDaemonListProtocols success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_list_protocols", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDaemonListProtocols service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonListProtocolsFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_list_protocols", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestErrDaemonServiceNameRequired(t *testing.T) {
	err := ErrDaemonServiceNameRequired{}
	expected := "service name is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

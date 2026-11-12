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

// TestDaemonGetConfigTool checks that platform_daemon_get_config passes
// the section argument to the provider and returns its result (#1689).
func TestDaemonGetConfigTool(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("passes the section", func(t *testing.T) {
		svc := newMockServiceProvider()
		var got string
		svc.daemonGetConfigFunc = func(ctx context.Context, section string) (interface{}, error) {
			got = section
			return map[string]interface{}{"section": section}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_get_config", map[string]interface{}{
			"section": "daemon",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if got != "daemon" {
			t.Fatalf("section = %q, want %q", got, "daemon")
		}
	})

	t.Run("empty section asks for every section", func(t *testing.T) {
		svc := newMockServiceProvider()
		got := "unset"
		svc.daemonGetConfigFunc = func(ctx context.Context, section string) (interface{}, error) {
			got = section
			return map[string]interface{}{}, nil
		}
		registry := NewToolRegistry(svc, log)

		if _, err := registry.ExecuteTool(ctx, "platform_daemon_get_config", map[string]interface{}{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("section = %q, want empty", got)
		}
	})

	t.Run("service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonGetConfigFunc = func(ctx context.Context, section string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_get_config", map[string]interface{}{})
		if !errors.Is(err, ErrMockServiceError) {
			t.Fatalf("err = %v, want ErrMockServiceError", err)
		}
	})

	t.Run("registered", func(t *testing.T) {
		registry := NewToolRegistry(newMockServiceProvider(), log)
		if !hasDaemonTool(registry, "platform_daemon_get_config") {
			t.Fatal("platform_daemon_get_config is not registered")
		}
	})
}

// TestDaemonReloadConfigTool checks that platform_daemon_reload_config
// calls the provider and returns its result (#1689).
func TestDaemonReloadConfigTool(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("success", func(t *testing.T) {
		svc := newMockServiceProvider()
		called := false
		svc.daemonReloadConfigFunc = func(ctx context.Context) (interface{}, error) {
			called = true
			return map[string]interface{}{"success": true}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_daemon_reload_config", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if !called {
			t.Fatal("DaemonReloadConfig was not called")
		}
	})

	t.Run("service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.daemonReloadConfigFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_daemon_reload_config", map[string]interface{}{})
		if !errors.Is(err, ErrMockServiceError) {
			t.Fatalf("err = %v, want ErrMockServiceError", err)
		}
	})

	t.Run("registered", func(t *testing.T) {
		registry := NewToolRegistry(newMockServiceProvider(), log)
		if !hasDaemonTool(registry, "platform_daemon_reload_config") {
			t.Fatal("platform_daemon_reload_config is not registered")
		}
	})
}

// hasDaemonTool reports whether the registry lists a tool by name.
func hasDaemonTool(r *ToolRegistry, name string) bool {
	for _, tool := range r.ListTools() {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func TestErrDaemonServiceNameRequired(t *testing.T) {
	err := ErrDaemonServiceNameRequired{}
	expected := "service name is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

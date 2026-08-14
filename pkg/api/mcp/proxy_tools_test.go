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
	"strings"
	"testing"
)

// proxyStubProvider is a configurable ProxyProvider test double recording
// the last invocation.
type proxyStubProvider struct {
	lastCall string
	lastArgs map[string]interface{}
	lastID   string
	result   interface{}
	err      error
}

func (s *proxyStubProvider) ProxyRouteCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	s.lastCall, s.lastArgs = "route_create", args
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyRouteGet(ctx context.Context, id string) (interface{}, error) {
	s.lastCall, s.lastID = "route_get", id
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyRouteUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	s.lastCall, s.lastArgs = "route_update", args
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyRouteDelete(ctx context.Context, id string) (interface{}, error) {
	s.lastCall, s.lastID = "route_delete", id
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyRouteList(ctx context.Context) (interface{}, error) {
	s.lastCall = "route_list"
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyPoolCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	s.lastCall, s.lastArgs = "pool_create", args
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyPoolGet(ctx context.Context, id string) (interface{}, error) {
	s.lastCall, s.lastID = "pool_get", id
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyPoolUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	s.lastCall, s.lastArgs = "pool_update", args
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyPoolDelete(ctx context.Context, id string) (interface{}, error) {
	s.lastCall, s.lastID = "pool_delete", id
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyPoolList(ctx context.Context) (interface{}, error) {
	s.lastCall = "pool_list"
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyConfig(ctx context.Context) (interface{}, error) {
	s.lastCall = "config"
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyStatus(ctx context.Context) (interface{}, error) {
	s.lastCall = "status"
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyConfigReload(ctx context.Context) (interface{}, error) {
	s.lastCall = "reload"
	return s.result, s.err
}

func (s *proxyStubProvider) ProxyZoneMatrix(ctx context.Context) (interface{}, error) {
	s.lastCall = "zone_matrix"
	return s.result, s.err
}

// proxyCombinedProvider satisfies ServiceProvider and ProxyProvider.
type proxyCombinedProvider struct {
	*mockServiceProvider
	*proxyStubProvider
}

// Compile-time assertions.
var (
	_ ServiceProvider = (*proxyCombinedProvider)(nil)
	_ ProxyProvider   = (*proxyCombinedProvider)(nil)
	_ ProxyProvider   = (*proxyStubProvider)(nil)
)

func newProxyRegistry() (*ToolRegistry, *proxyStubProvider) {
	stub := &proxyStubProvider{result: map[string]interface{}{"version": 1}}
	svc := &proxyCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		proxyStubProvider:   stub,
	}
	return NewToolRegistry(svc, newTestLogger()), stub
}

// expectedProxyTools is the canonical proxy tool set.
var expectedProxyTools = []string{
	"proxy_route_create",
	"proxy_route_get",
	"proxy_route_update",
	"proxy_route_delete",
	"proxy_route_list",
	"proxy_pool_create",
	"proxy_pool_get",
	"proxy_pool_update",
	"proxy_pool_delete",
	"proxy_pool_list",
	"proxy_config",
	"proxy_status",
	"proxy_config_reload",
	"proxy_zone_matrix",
}

// TestProxyToolRegistrationAndRoutingParity asserts every proxy_* tool is
// registered, the dispatch map matches the registered set, and ExecuteTool
// routes each tool to the proxy executor (a provider without ProxyProvider
// yields ErrProxyNotConfigured, never "unknown tool").
func TestProxyToolRegistrationAndRoutingParity(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		if strings.HasPrefix(tool.Name, "proxy_") {
			registered[tool.Name] = true
		}
	}

	for _, name := range expectedProxyTools {
		if !registered[name] {
			t.Errorf("tool %s not registered", name)
		}
		if _, ok := proxyToolDispatch[name]; !ok {
			t.Errorf("tool %s not in dispatch map", name)
		}
		delete(registered, name)
	}
	for name := range registered {
		t.Errorf("unexpected proxy tool registered: %s", name)
	}
	if len(proxyToolDispatch) != len(expectedProxyTools) {
		t.Errorf("dispatch map has %d entries, want %d", len(proxyToolDispatch), len(expectedProxyTools))
	}

	// Without a ProxyProvider every proxy tool must surface the typed
	// not-configured error through the real ExecuteTool path. Tools with
	// required arguments receive them so argument validation does not
	// mask the routing assertion.
	argsFor := map[string]map[string]interface{}{
		"proxy_route_create": {"route": map[string]interface{}{"id": "web"}},
		"proxy_route_update": {"route": map[string]interface{}{"id": "web"}},
		"proxy_pool_create":  {"pool": map[string]interface{}{"id": "p"}},
		"proxy_pool_update":  {"pool": map[string]interface{}{"id": "p"}},
		"proxy_route_get":    {"id": "web"},
		"proxy_route_delete": {"id": "web"},
		"proxy_pool_get":     {"id": "p"},
		"proxy_pool_delete":  {"id": "p"},
	}
	for _, name := range expectedProxyTools {
		args := argsFor[name]
		if args == nil {
			args = map[string]interface{}{}
		}
		_, err := registry.ExecuteTool(ctx, name, args)
		if !errors.Is(err, ErrProxyNotConfigured) {
			t.Errorf("ExecuteTool(%s) err = %v, want ErrProxyNotConfigured", name, err)
		}
	}
}

func TestProxyTools_RouteExecutors(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProxyRegistry()

	// Create routes args straight through to the provider.
	routeArgs := map[string]interface{}{"route": map[string]interface{}{"id": "web"}}
	if _, err := registry.ExecuteTool(ctx, "proxy_route_create", routeArgs); err != nil {
		t.Fatalf("proxy_route_create: %v", err)
	}
	if stub.lastCall != "route_create" || stub.lastArgs["route"] == nil {
		t.Errorf("provider call = %s args %v", stub.lastCall, stub.lastArgs)
	}

	if _, err := registry.ExecuteTool(ctx, "proxy_route_get", map[string]interface{}{"id": "web"}); err != nil {
		t.Fatalf("proxy_route_get: %v", err)
	}
	if stub.lastCall != "route_get" || stub.lastID != "web" {
		t.Errorf("provider call = %s id %s", stub.lastCall, stub.lastID)
	}

	if _, err := registry.ExecuteTool(ctx, "proxy_route_update", routeArgs); err != nil {
		t.Fatalf("proxy_route_update: %v", err)
	}
	if stub.lastCall != "route_update" {
		t.Errorf("provider call = %s, want route_update", stub.lastCall)
	}

	if _, err := registry.ExecuteTool(ctx, "proxy_route_delete", map[string]interface{}{"id": "web"}); err != nil {
		t.Fatalf("proxy_route_delete: %v", err)
	}
	if stub.lastCall != "route_delete" || stub.lastID != "web" {
		t.Errorf("provider call = %s id %s", stub.lastCall, stub.lastID)
	}

	result, err := registry.ExecuteTool(ctx, "proxy_route_list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("proxy_route_list: %v", err)
	}
	if stub.lastCall != "route_list" {
		t.Errorf("provider call = %s, want route_list", stub.lastCall)
	}
	// marshalResult normalizes to canonical JSON types.
	m, ok := result.(map[string]interface{})
	if !ok || m["version"] != float64(1) {
		t.Errorf("result = %#v, want map with version 1", result)
	}
}

func TestProxyTools_RouteExecutors_ArgumentErrors(t *testing.T) {
	ctx := context.Background()
	registry, _ := newProxyRegistry()

	if _, err := registry.ExecuteTool(ctx, "proxy_route_create", map[string]interface{}{}); !errors.Is(err, ErrProxyRouteRequired) {
		t.Errorf("route_create err = %v, want ErrProxyRouteRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_route_update", map[string]interface{}{}); !errors.Is(err, ErrProxyRouteRequired) {
		t.Errorf("route_update err = %v, want ErrProxyRouteRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_route_get", map[string]interface{}{}); !errors.Is(err, ErrProxyIDRequired) {
		t.Errorf("route_get err = %v, want ErrProxyIDRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_route_delete", map[string]interface{}{}); !errors.Is(err, ErrProxyIDRequired) {
		t.Errorf("route_delete err = %v, want ErrProxyIDRequired", err)
	}
}

func TestProxyTools_PoolExecutors(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProxyRegistry()

	poolArgs := map[string]interface{}{"pool": map[string]interface{}{"id": "p1"}}
	steps := []struct {
		tool string
		args map[string]interface{}
		call string
	}{
		{"proxy_pool_create", poolArgs, "pool_create"},
		{"proxy_pool_get", map[string]interface{}{"id": "p1"}, "pool_get"},
		{"proxy_pool_update", poolArgs, "pool_update"},
		{"proxy_pool_delete", map[string]interface{}{"id": "p1"}, "pool_delete"},
		{"proxy_pool_list", map[string]interface{}{}, "pool_list"},
	}
	for _, step := range steps {
		if _, err := registry.ExecuteTool(ctx, step.tool, step.args); err != nil {
			t.Fatalf("%s: %v", step.tool, err)
		}
		if stub.lastCall != step.call {
			t.Errorf("%s routed to %s, want %s", step.tool, stub.lastCall, step.call)
		}
	}
}

func TestProxyTools_PoolExecutors_ArgumentErrors(t *testing.T) {
	ctx := context.Background()
	registry, _ := newProxyRegistry()

	if _, err := registry.ExecuteTool(ctx, "proxy_pool_create", map[string]interface{}{}); !errors.Is(err, ErrProxyPoolRequired) {
		t.Errorf("pool_create err = %v, want ErrProxyPoolRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_pool_update", map[string]interface{}{}); !errors.Is(err, ErrProxyPoolRequired) {
		t.Errorf("pool_update err = %v, want ErrProxyPoolRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_pool_get", map[string]interface{}{}); !errors.Is(err, ErrProxyIDRequired) {
		t.Errorf("pool_get err = %v, want ErrProxyIDRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_pool_delete", map[string]interface{}{}); !errors.Is(err, ErrProxyIDRequired) {
		t.Errorf("pool_delete err = %v, want ErrProxyIDRequired", err)
	}
}

func TestProxyTools_ConfigStatusReloadMatrix(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProxyRegistry()

	for tool, call := range map[string]string{
		"proxy_config":        "config",
		"proxy_status":        "status",
		"proxy_config_reload": "reload",
		"proxy_zone_matrix":   "zone_matrix",
	} {
		if _, err := registry.ExecuteTool(ctx, tool, map[string]interface{}{}); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if stub.lastCall != call {
			t.Errorf("%s routed to %s, want %s", tool, stub.lastCall, call)
		}
	}
}

func TestProxyTools_ProviderErrorPropagates(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProxyRegistry()
	stub.err = ErrMockServiceError

	if _, err := registry.ExecuteTool(ctx, "proxy_status", map[string]interface{}{}); !errors.Is(err, ErrMockServiceError) {
		t.Errorf("err = %v, want ErrMockServiceError", err)
	}
	if _, err := registry.ExecuteTool(ctx, "proxy_route_get", map[string]interface{}{"id": "web"}); !errors.Is(err, ErrMockServiceError) {
		t.Errorf("err = %v, want ErrMockServiceError", err)
	}
}

func TestProxyTools_Permissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	expected := map[string]string{
		"proxy_route_create":  "proxy:write",
		"proxy_route_get":     "proxy:read",
		"proxy_route_update":  "proxy:write",
		"proxy_route_delete":  "proxy:delete",
		"proxy_route_list":    "proxy:read",
		"proxy_pool_create":   "proxy:write",
		"proxy_pool_get":      "proxy:read",
		"proxy_pool_update":   "proxy:write",
		"proxy_pool_delete":   "proxy:delete",
		"proxy_pool_list":     "proxy:read",
		"proxy_config":        "proxy:read",
		"proxy_status":        "proxy:read",
		"proxy_config_reload": "proxy:write",
		"proxy_zone_matrix":   "proxy:read",
	}
	for tool, want := range expected {
		if got := checker.toolPermissions[tool]; got != want {
			t.Errorf("permission[%s] = %q, want %q", tool, got, want)
		}
	}
}

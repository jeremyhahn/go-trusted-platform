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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Test fixtures
// =============================================================================

// clusterStubProvider is a minimal ClusterProvider that records the last
// invoked method so tests can assert dispatch.
type clusterStubProvider struct {
	lastCall string
	failWith error
}

func (s *clusterStubProvider) ClusterBootstrap(_ context.Context, clusterName string) (interface{}, error) {
	s.lastCall = "bootstrap:" + clusterName
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{"cluster_name": clusterName, "bootstrap": true}, nil
}

func (s *clusterStubProvider) ClusterJoin(_ context.Context, addresses []string) (interface{}, error) {
	s.lastCall = "join:" + strings.Join(addresses, ",")
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{"seed_addresses": addresses, "joined": true}, nil
}

func (s *clusterStubProvider) ClusterLeave(_ context.Context) (interface{}, error) {
	s.lastCall = "leave"
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{"left": true}, nil
}

func (s *clusterStubProvider) ClusterStatus(_ context.Context, includeNodes bool) (interface{}, error) {
	if includeNodes {
		s.lastCall = "status:nodes"
	} else {
		s.lastCall = "status"
	}
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{"include_nodes": includeNodes}, nil
}

func (s *clusterStubProvider) ClusterListNodes(_ context.Context) (interface{}, error) {
	s.lastCall = "list_nodes"
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{"nodes": []map[string]interface{}{}}, nil
}

// clusterCombinedProvider satisfies both ServiceProvider (via
// mockServiceProvider) and ClusterProvider (via clusterStubProvider).
// The two types contribute disjoint method sets so embedding is
// collision-free.
type clusterCombinedProvider struct {
	*mockServiceProvider
	*clusterStubProvider
}

// Compile-time assertions: combined provider satisfies both interfaces.
var (
	_ ServiceProvider = (*clusterCombinedProvider)(nil)
	_ ClusterProvider = (*clusterCombinedProvider)(nil)
)

// =============================================================================
// Tests: dispatch
// =============================================================================

// TestToolRegistry_ExecuteTool_Cluster_RoutesToProvider verifies that the
// ExecuteTool dispatcher routes platform_cluster_* tools through the
// optional ClusterProvider interface.
func TestToolRegistry_ExecuteTool_Cluster_RoutesToProvider(t *testing.T) {
	stub := &clusterStubProvider{}
	svc := &clusterCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		clusterStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name     string
		args     map[string]interface{}
		wantCall string
	}{
		{
			name:     "platform_cluster_bootstrap",
			args:     map[string]interface{}{"cluster_name": "alpha"},
			wantCall: "bootstrap:alpha",
		},
		{
			name:     "platform_cluster_bootstrap_no_name",
			args:     map[string]interface{}{},
			wantCall: "bootstrap:",
		},
		{
			name:     "platform_cluster_join",
			args:     map[string]interface{}{"seed_addresses": []interface{}{"10.0.0.1:7001", "10.0.0.2:7001"}},
			wantCall: "join:10.0.0.1:7001,10.0.0.2:7001",
		},
		{
			name:     "platform_cluster_leave",
			args:     map[string]interface{}{},
			wantCall: "leave",
		},
		{
			name:     "platform_cluster_status",
			args:     map[string]interface{}{},
			wantCall: "status",
		},
		{
			name:     "platform_cluster_status_include_nodes",
			args:     map[string]interface{}{"include_nodes": true},
			wantCall: "status:nodes",
		},
		{
			name:     "platform_cluster_list_nodes",
			args:     map[string]interface{}{},
			wantCall: "list_nodes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolName := tc.name
			// Strip suffix-only test labels back to the canonical tool name.
			switch toolName {
			case "platform_cluster_bootstrap_no_name":
				toolName = "platform_cluster_bootstrap"
			case "platform_cluster_status_include_nodes":
				toolName = "platform_cluster_status"
			}
			result, err := registry.ExecuteTool(ctx, toolName, tc.args)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if result == nil {
				t.Errorf("%s: result should not be nil", tc.name)
			}
			if stub.lastCall != tc.wantCall {
				t.Errorf("%s: lastCall = %q, want %q", tc.name, stub.lastCall, tc.wantCall)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Cluster_NoProvider verifies that cluster
// tools return ErrClusterNotConfigured when the ServiceProvider does
// not also satisfy ClusterProvider.
func TestToolRegistry_ExecuteTool_Cluster_NoProvider(t *testing.T) {
	// Plain mockServiceProvider does NOT satisfy ClusterProvider.
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"platform_cluster_bootstrap", map[string]interface{}{}},
		{"platform_cluster_join", map[string]interface{}{"seed_addresses": []interface{}{"x:1"}}},
		{"platform_cluster_leave", map[string]interface{}{}},
		{"platform_cluster_status", map[string]interface{}{}},
		{"platform_cluster_list_nodes", map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(err, ErrClusterNotConfigured) {
				t.Errorf("%s: expected ErrClusterNotConfigured, got %v", tc.name, err)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Cluster_JoinWithoutAddresses verifies that
// platform_cluster_join surfaces ErrClusterSeedAddressRequired when no
// seed addresses are supplied.
func TestToolRegistry_ExecuteTool_Cluster_JoinWithoutAddresses(t *testing.T) {
	stub := &clusterStubProvider{}
	svc := &clusterCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		clusterStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	// Empty args -> seed_addresses missing.
	_, err := registry.ExecuteTool(ctx, "platform_cluster_join", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing seed_addresses, got nil")
	}
	if !errors.Is(err, ErrClusterSeedAddressRequired) {
		t.Errorf("expected ErrClusterSeedAddressRequired, got %v", err)
	}

	// Empty slice -> still missing.
	_, err = registry.ExecuteTool(ctx, "platform_cluster_join", map[string]interface{}{
		"seed_addresses": []interface{}{},
	})
	if err == nil {
		t.Fatal("expected error for empty seed_addresses, got nil")
	}
	if !errors.Is(err, ErrClusterSeedAddressRequired) {
		t.Errorf("expected ErrClusterSeedAddressRequired, got %v", err)
	}

	// Provider should never have been called.
	if stub.lastCall != "" {
		t.Errorf("provider should not have been invoked; lastCall = %q", stub.lastCall)
	}
}

// TestToolRegistry_ExecuteTool_Cluster_PropagatesError verifies that
// errors returned by the ClusterProvider propagate unchanged through
// ExecuteTool (no error wrapping that would break errors.Is).
func TestToolRegistry_ExecuteTool_Cluster_PropagatesError(t *testing.T) {
	sentinel := errors.New("cluster: boom")
	stub := &clusterStubProvider{failWith: sentinel}
	svc := &clusterCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		clusterStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"platform_cluster_bootstrap", map[string]interface{}{}},
		{"platform_cluster_join", map[string]interface{}{"seed_addresses": []interface{}{"x:1"}}},
		{"platform_cluster_leave", map[string]interface{}{}},
		{"platform_cluster_status", map[string]interface{}{}},
		{"platform_cluster_list_nodes", map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if !errors.Is(err, sentinel) {
				t.Errorf("%s: expected sentinel error, got %v", tc.name, err)
			}
		})
	}
}

// TestToolRegistry_ClusterToolsRegistered verifies all platform_cluster_*
// tool definitions are registered and listable.
func TestToolRegistry_ClusterToolsRegistered(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	expected := []string{
		"platform_cluster_bootstrap",
		"platform_cluster_join",
		"platform_cluster_leave",
		"platform_cluster_status",
		"platform_cluster_list_nodes",
	}
	tools := registry.ListTools()
	got := make(map[string]struct{}, len(tools))
	for _, td := range tools {
		got[td.Name] = struct{}{}
	}
	for _, name := range expected {
		if _, ok := got[name]; !ok {
			t.Errorf("missing registered tool: %s", name)
		}
	}
}

// TestDispatchClusterTool_UnknownReturnsHandledFalse verifies that the
// cluster dispatcher returns handled=false for tool names that are not
// platform_cluster_*. This lets the central ExecuteTool fall through to
// other dispatchers and ultimately the unknown-tool error.
func TestDispatchClusterTool_UnknownReturnsHandledFalse(t *testing.T) {
	stub := &clusterStubProvider{}
	svc := &clusterCombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		clusterStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	result, handled, err := registry.dispatchClusterTool(ctx, "platform_bmc_power_on", map[string]interface{}{})
	if handled {
		t.Errorf("expected handled=false for non-cluster tool, got true")
	}
	if err != nil {
		t.Errorf("expected nil error for non-cluster tool, got %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for non-cluster tool, got %v", result)
	}
}

// TestClusterProvider_NilFromRegistry verifies that the clusterProvider()
// helper returns nil when the wrapped ServiceProvider does not satisfy
// ClusterProvider. The downstream effect is ErrClusterNotConfigured.
func TestClusterProvider_NilFromRegistry(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	if p := registry.clusterProvider(); p != nil {
		t.Fatalf("expected nil ClusterProvider, got %T", p)
	}
}

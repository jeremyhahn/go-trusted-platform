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
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Test fixtures
// =============================================================================

// registryStubProvider is a minimal RegistryProvider that records the
// last invoked method so tests can assert dispatch.
type registryStubProvider struct {
	lastCall      string
	lastListQuery RegistryListQuery
	failWith      error
}

func (s *registryStubProvider) RegistryList(_ context.Context, query RegistryListQuery) (interface{}, error) {
	s.lastCall = "list"
	s.lastListQuery = query
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{
		"repository":    query.Repository,
		"artifact_type": query.ArtifactType,
		"limit":         query.Limit,
		"offset":        query.Offset,
		"artifacts":     []map[string]interface{}{},
	}, nil
}

func (s *registryStubProvider) RegistryInspect(_ context.Context, repository, reference, digest string, includeSignatures, includeScanResult bool) (interface{}, error) {
	s.lastCall = "inspect:" + repository + ":" + reference + ":" + digest
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{
		"repository":          repository,
		"reference":           reference,
		"digest":              digest,
		"include_signatures":  includeSignatures,
		"include_scan_result": includeScanResult,
	}, nil
}

func (s *registryStubProvider) RegistryDelete(_ context.Context, repository, reference, digest string, force bool) (interface{}, error) {
	s.lastCall = "delete:" + repository + ":" + reference + ":" + digest
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{
		"repository": repository,
		"force":      force,
	}, nil
}

func (s *registryStubProvider) RegistryStatus(_ context.Context) (interface{}, error) {
	s.lastCall = "status"
	if s.failWith != nil {
		return nil, s.failWith
	}
	return map[string]interface{}{
		"health":  "healthy",
		"version": "1.0.0",
	}, nil
}

// registryCombinedProvider satisfies both ServiceProvider (via
// mockServiceProvider) and RegistryProvider (via registryStubProvider).
// The two contribute disjoint method sets so embedding is collision-free.
type registryCombinedProvider struct {
	*mockServiceProvider
	*registryStubProvider
}

// Compile-time assertions: combined provider satisfies both interfaces.
var (
	_ ServiceProvider  = (*registryCombinedProvider)(nil)
	_ RegistryProvider = (*registryCombinedProvider)(nil)
)

// =============================================================================
// Dispatch routing
// =============================================================================

// TestToolRegistry_ExecuteTool_Registry_RoutesToProvider verifies that
// the ExecuteTool dispatcher routes platform_registry_* tools through
// the optional RegistryProvider interface.
func TestToolRegistry_ExecuteTool_Registry_RoutesToProvider(t *testing.T) {
	stub := &registryStubProvider{}
	svc := &registryCombinedProvider{
		mockServiceProvider:  newMockServiceProvider(),
		registryStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name     string
		args     map[string]interface{}
		wantCall string
	}{
		{
			name:     "platform_registry_list",
			args:     map[string]interface{}{"repository": "platform/gateway", "limit": 25},
			wantCall: "list",
		},
		{
			name: "platform_registry_inspect",
			args: map[string]interface{}{
				"repository":          "platform/gateway",
				"reference":           "v1.2.3",
				"include_signatures":  true,
				"include_scan_result": true,
			},
			wantCall: "inspect:platform/gateway:v1.2.3:",
		},
		{
			name: "platform_registry_inspect_by_digest",
			args: map[string]interface{}{
				"repository": "platform/gateway",
				"digest":     "sha256:abc",
			},
			wantCall: "inspect:platform/gateway::sha256:abc",
		},
		{
			name: "platform_registry_delete",
			args: map[string]interface{}{
				"repository": "platform/gateway",
				"reference":  "v1.2.3",
				"force":      true,
			},
			wantCall: "delete:platform/gateway:v1.2.3:",
		},
		{
			name:     "platform_registry_status",
			args:     map[string]interface{}{},
			wantCall: "status",
		},
	}
	// platform_registry_inspect_by_digest reuses the inspect tool name.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolName := tc.name
			if toolName == "platform_registry_inspect_by_digest" {
				toolName = "platform_registry_inspect"
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

// TestToolRegistry_ExecuteTool_RegistryList_ForwardsEveryArgument verifies
// platform_registry_list hands every schema argument — including the
// cursor, sort and label-selector fields the SDK List carries — to the
// provider unchanged.
func TestToolRegistry_ExecuteTool_RegistryList_ForwardsEveryArgument(t *testing.T) {
	stub := &registryStubProvider{}
	svc := &registryCombinedProvider{
		mockServiceProvider:  newMockServiceProvider(),
		registryStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	args := map[string]interface{}{
		"repository":        "platform/gateway",
		"artifact_type":     float64(1),
		"limit":             float64(25),
		"offset":            float64(50),
		"cursor":            "cursor-a",
		"sort_by":           "created_at",
		"ascending":         true,
		"match_labels":      map[string]interface{}{"env": "prod"},
		"match_expressions": []interface{}{"tier in (edge)"},
	}
	if _, err := registry.ExecuteTool(context.Background(), "platform_registry_list", args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := RegistryListQuery{
		Repository:       "platform/gateway",
		ArtifactType:     1,
		Limit:            25,
		Offset:           50,
		Cursor:           "cursor-a",
		SortBy:           "created_at",
		Ascending:        true,
		MatchLabels:      map[string]string{"env": "prod"},
		MatchExpressions: []string{"tier in (edge)"},
	}
	if !reflect.DeepEqual(stub.lastListQuery, want) {
		t.Errorf("query = %+v, want %+v", stub.lastListQuery, want)
	}
}

// TestToolRegistry_ExecuteTool_Registry_NoProvider verifies that registry
// tools return ErrRegistryNotConfigured when the ServiceProvider does
// not also satisfy RegistryProvider.
func TestToolRegistry_ExecuteTool_Registry_NoProvider(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{
			name: "platform_registry_list",
			args: map[string]interface{}{},
		},
		{
			name: "platform_registry_inspect",
			args: map[string]interface{}{"repository": "x", "reference": "latest"},
		},
		{
			name: "platform_registry_delete",
			args: map[string]interface{}{"repository": "x", "reference": "latest"},
		},
		{
			name: "platform_registry_status",
			args: map[string]interface{}{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(err, ErrRegistryNotConfigured) {
				t.Errorf("%s: expected ErrRegistryNotConfigured, got %v", tc.name, err)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Registry_MissingArgs verifies argument
// validation for inspect/delete: missing repository -> repo error;
// missing reference + digest -> reference error.
func TestToolRegistry_ExecuteTool_Registry_MissingArgs(t *testing.T) {
	stub := &registryStubProvider{}
	svc := &registryCombinedProvider{
		mockServiceProvider:  newMockServiceProvider(),
		registryStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name      string
		toolName  string
		args      map[string]interface{}
		wantErr   error
		wantCall  string
		shouldDis bool
	}{
		{
			name:     "inspect missing repo",
			toolName: "platform_registry_inspect",
			args:     map[string]interface{}{"reference": "latest"},
			wantErr:  ErrRegistryRepositoryRequired,
		},
		{
			name:     "inspect missing reference and digest",
			toolName: "platform_registry_inspect",
			args:     map[string]interface{}{"repository": "x"},
			wantErr:  ErrRegistryReferenceRequired,
		},
		{
			name:     "delete missing repo",
			toolName: "platform_registry_delete",
			args:     map[string]interface{}{"reference": "latest"},
			wantErr:  ErrRegistryRepositoryRequired,
		},
		{
			name:     "delete missing reference and digest",
			toolName: "platform_registry_delete",
			args:     map[string]interface{}{"repository": "x"},
			wantErr:  ErrRegistryReferenceRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.toolName, tc.args)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Registry_ProviderError verifies that
// errors returned by the provider propagate unchanged.
func TestToolRegistry_ExecuteTool_Registry_ProviderError(t *testing.T) {
	want := errors.New("upstream registry failure")
	stub := &registryStubProvider{failWith: want}
	svc := &registryCombinedProvider{
		mockServiceProvider:  newMockServiceProvider(),
		registryStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	_, err := registry.ExecuteTool(ctx, "platform_registry_status", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, want) {
		t.Errorf("expected %v, got %v", want, err)
	}
}

// TestToolRegistry_RegistryToolsRegistered verifies all
// platform_registry_* tool definitions are listable.
func TestToolRegistry_RegistryToolsRegistered(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	expected := []string{
		"platform_registry_list",
		"platform_registry_inspect",
		"platform_registry_delete",
		"platform_registry_status",
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

// TestRegistryProvider_DispatchMap verifies that dispatchRegistryTool
// returns handled=false for tool names outside the registry namespace
// so the parent dispatcher can fall through to other handlers.
func TestRegistryProvider_DispatchMap_Unhandled(t *testing.T) {
	stub := &registryStubProvider{}
	svc := &registryCombinedProvider{
		mockServiceProvider:  newMockServiceProvider(),
		registryStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	result, handled, err := registry.dispatchRegistryTool(context.Background(), "not_a_registry_tool", nil)
	if handled {
		t.Errorf("expected handled=false for non-registry tool")
	}
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
}

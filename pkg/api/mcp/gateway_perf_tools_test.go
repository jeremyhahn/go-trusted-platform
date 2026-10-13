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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// newPerfToolRegistry builds a tool registry backed by the shared mock
// provider.
func newPerfToolRegistry(provider *mockServiceProvider) *ToolRegistry {
	return NewToolRegistry(provider, newTestLogger())
}

func TestGatewayPerfToolsRegistered(t *testing.T) {
	registry := newPerfToolRegistry(&mockServiceProvider{})
	tools := registry.ListTools()

	want := map[string]bool{
		"gateway_perf_flows":     false,
		"gateway_perf_datapath":  false,
		"gateway_perf_conntrack": false,
	}
	for _, tool := range tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %s not registered", name)
		}
	}
}

func TestDispatchGatewayPerfToolUnknownName(t *testing.T) {
	registry := newPerfToolRegistry(&mockServiceProvider{})

	_, handled, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_lb_status", nil)
	if handled {
		t.Error("handled = true for non-perf tool")
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestExecuteGatewayPerfFlows(t *testing.T) {
	provider := &mockServiceProvider{}
	registry := newPerfToolRegistry(provider)

	result, handled, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_flows", map[string]interface{}{
		"count":  float64(500),
		"batch":  true,
		"bridge": "br-int",
	})
	if !handled {
		t.Fatal("handled = false")
	}
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil")
	}
	if len(provider.perfFlowsCalls) != 1 {
		t.Fatalf("perfFlowsCalls = %d, want 1", len(provider.perfFlowsCalls))
	}
	call := provider.perfFlowsCalls[0]
	if call.count != 500 || !call.batch || call.bridge != "br-int" {
		t.Errorf("call = %+v", call)
	}
}

func TestExecuteGatewayPerfFlowsInvalidCount(t *testing.T) {
	registry := newPerfToolRegistry(&mockServiceProvider{})

	_, handled, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_flows", map[string]interface{}{
		"count": float64(1000000),
	})
	if !handled {
		t.Fatal("handled = false")
	}
	if !errors.Is(err, ErrPerfInvalidCount) {
		t.Fatalf("err = %v, want ErrPerfInvalidCount", err)
	}
}

func TestExecuteGatewayPerfFlowsProviderError(t *testing.T) {
	provider := &mockServiceProvider{perfErr: ErrMockServiceError}
	registry := newPerfToolRegistry(provider)

	_, handled, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_flows", map[string]interface{}{
		"count": float64(10),
	})
	if !handled {
		t.Fatal("handled = false")
	}
	if !errors.Is(err, ErrMockServiceError) {
		t.Fatalf("err = %v, want mock error", err)
	}
}

func TestExecuteGatewayPerfDatapath(t *testing.T) {
	registry := newPerfToolRegistry(&mockServiceProvider{})

	result, handled, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_datapath", map[string]interface{}{})
	if !handled {
		t.Fatal("handled = false")
	}
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil")
	}
}

func TestExecuteGatewayPerfDatapathProviderError(t *testing.T) {
	registry := newPerfToolRegistry(&mockServiceProvider{perfErr: ErrMockServiceError})

	_, _, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_datapath", map[string]interface{}{})
	if !errors.Is(err, ErrMockServiceError) {
		t.Fatalf("err = %v, want mock error", err)
	}
}

func TestExecuteGatewayPerfConntrackAllZones(t *testing.T) {
	provider := &mockServiceProvider{}
	registry := newPerfToolRegistry(provider)

	_, handled, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_conntrack", map[string]interface{}{})
	if !handled {
		t.Fatal("handled = false")
	}
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(provider.perfConntrackZones) != 1 || provider.perfConntrackZones[0] != -1 {
		t.Errorf("zones = %v, want [-1]", provider.perfConntrackZones)
	}
}

func TestExecuteGatewayPerfConntrackSpecificZone(t *testing.T) {
	provider := &mockServiceProvider{}
	registry := newPerfToolRegistry(provider)

	_, _, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_conntrack", map[string]interface{}{
		"zone": float64(12),
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(provider.perfConntrackZones) != 1 || provider.perfConntrackZones[0] != 12 {
		t.Errorf("zones = %v, want [12]", provider.perfConntrackZones)
	}
}

func TestExecuteGatewayPerfConntrackInvalidZone(t *testing.T) {
	registry := newPerfToolRegistry(&mockServiceProvider{})

	_, _, err := registry.dispatchGatewayPerfTool(context.Background(), "gateway_perf_conntrack", map[string]interface{}{
		"zone": float64(70000),
	})
	if !errors.Is(err, ErrPerfInvalidZone) {
		t.Fatalf("err = %v, want ErrPerfInvalidZone", err)
	}
}

func TestGatewayPerfToolPermissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	cases := map[string]string{
		"gateway_perf_flows":     "sdn:write",
		"gateway_perf_datapath":  "sdn:read",
		"gateway_perf_conntrack": "sdn:read",
	}
	for tool, want := range cases {
		if got := checker.toolPermissions[tool]; got != want {
			t.Errorf("permission for %s = %q, want %q", tool, got, want)
		}
	}
}

func TestGatewayAdmittedVTEPToolPermissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	for _, tool := range []string{"gateway_admitted_vtep", "gateway_admitted_vteps"} {
		if got := checker.toolPermissions[tool]; got != "sdn:read" {
			t.Errorf("permission for %s = %q, want %q", tool, got, "sdn:read")
		}
	}
}

// admissionProvider answers the admitted-VTEP tools with fixed values.
type admissionProvider struct {
	*mockServiceProvider
	vtep  interface{}
	vteps []interface{}
	err   error
}

func (p admissionProvider) GatewayAdmittedVTEP(context.Context, string, string) (interface{}, error) {
	return p.vtep, p.err
}

func (p admissionProvider) GatewayAdmittedVTEPs(context.Context, string) ([]interface{}, error) {
	return p.vteps, p.err
}

func TestExecuteGatewayAdmittedVTEPTools(t *testing.T) {
	provider := admissionProvider{
		mockServiceProvider: newMockServiceProvider(),
		vtep:                "198.51.100.10",
		vteps:               []interface{}{"198.51.100.10", "198.51.100.11"},
	}
	registry := NewToolRegistry(provider, newTestLogger())

	got, err := registry.executeGatewayAdmittedVTEP(context.Background(), map[string]interface{}{"gateway_id": "gw-1", "vtep": "198.51.100.10"})
	if err != nil || got != "198.51.100.10" {
		t.Fatalf("admitted_vtep = %v, %v", got, err)
	}
	list, err := registry.executeGatewayAdmittedVTEPs(context.Background(), map[string]interface{}{"gateway_id": "gw-1"})
	if err != nil {
		t.Fatalf("admitted_vteps: %v", err)
	}
	if reply, ok := list.(map[string]interface{}); !ok || reply["count"] != 2 {
		t.Fatalf("admitted_vteps = %+v, want a count of 2", list)
	}
}

// The provider's status class must reach the MCP client: an unknown
// gateway or VTEP is NotFound there as it is over gRPC and REST.
func TestExecuteGatewayAdmittedVTEPToolsKeepProviderClass(t *testing.T) {
	notFound := status.Error(codes.NotFound, "gateway gw-9 has reported no overlay")
	registry := NewToolRegistry(admissionProvider{mockServiceProvider: newMockServiceProvider(), err: notFound}, newTestLogger())

	_, oneErr := registry.executeGatewayAdmittedVTEP(context.Background(), map[string]interface{}{"gateway_id": "gw-9", "vtep": "198.51.100.10"})
	_, listErr := registry.executeGatewayAdmittedVTEPs(context.Background(), map[string]interface{}{"gateway_id": "gw-9"})
	for name, err := range map[string]error{"admitted_vtep": oneErr, "admitted_vteps": listErr} {
		if code := toolErrorCode(err); code != mcpwire.NotFound {
			t.Errorf("%s: toolErrorCode(%v) = %d, want NotFound", name, err, code)
		}
	}
}

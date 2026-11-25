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

// windowCaptureProvider records the IPAM pool requests the tools build.
type windowCaptureProvider struct {
	*mockServiceProvider
	create *IPAMPoolCreateRequest
	update *IPAMPoolUpdateRequest
}

func (p *windowCaptureProvider) GatewayIPAMPoolCreate(_ context.Context, req *IPAMPoolCreateRequest) (interface{}, error) {
	p.create = req
	return map[string]interface{}{"id": "pool"}, nil
}

func (p *windowCaptureProvider) GatewayIPAMPoolUpdate(_ context.Context, id string, req *IPAMPoolUpdateRequest) (interface{}, error) {
	p.update = req
	return map[string]interface{}{"id": id}, nil
}

// TestGatewayIPAMPoolTools_Window verifies the create and update tools pass
// the allocation window through, and that update tells "clear" from "keep".
func TestGatewayIPAMPoolTools_Window(t *testing.T) {
	ctx := context.Background()
	svc := &windowCaptureProvider{mockServiceProvider: newMockServiceProvider()}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "gateway_ipam_pool_create", map[string]interface{}{
		"name":        "lab",
		"cidr":        "10.4.9.0/24",
		"reserved":    []interface{}{"10.4.9.1/32"},
		"range_start": "10.4.9.50",
		"range_end":   "10.4.9.254",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(svc.create.Reserved) != 1 || svc.create.RangeStart != "10.4.9.50" || svc.create.RangeEnd != "10.4.9.254" {
		t.Fatalf("create window not passed: %+v", svc.create)
	}

	// Only range_start given: reserved and range_end are kept (nil).
	_, err = registry.ExecuteTool(ctx, "gateway_ipam_pool_update", map[string]interface{}{
		"pool_id":     "lab",
		"range_start": "",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if svc.update.RangeStart == nil || *svc.update.RangeStart != "" {
		t.Fatalf("an explicit empty range_start must clear the bound: %+v", svc.update)
	}
	if svc.update.RangeEnd != nil || svc.update.Reserved != nil {
		t.Fatalf("omitted window fields must be kept: %+v", svc.update)
	}

	// An empty reserved list clears the reservations.
	_, err = registry.ExecuteTool(ctx, "gateway_ipam_pool_update", map[string]interface{}{
		"pool_id":  "lab",
		"reserved": []interface{}{},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if svc.update.Reserved == nil || len(svc.update.Reserved) != 0 {
		t.Fatalf("an empty reserved list must clear: %+v", svc.update)
	}
}

// TestGetOptionalString distinguishes an absent argument from an empty one
// and ignores a non-string value.
func TestGetOptionalString(t *testing.T) {
	args := map[string]interface{}{"set": "x", "empty": "", "number": 3}
	if v := getOptionalString(args, "set"); v == nil || *v != "x" {
		t.Fatalf("set: %v", v)
	}
	if v := getOptionalString(args, "empty"); v == nil || *v != "" {
		t.Fatalf("empty: %v", v)
	}
	if getOptionalString(args, "missing") != nil || getOptionalString(args, "number") != nil {
		t.Fatal("absent or non-string arguments must be nil")
	}
}

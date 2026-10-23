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

// Package mcp provides the MCP (Model Context Protocol) transport adapter for the platform SDK.
// It wraps the pkg/api/mcp client and provides a gRPC-compatible interface
// for service clients, using JSON-RPC 2.0 over HTTP.
package mcp

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestMethodTools_MatchesDispatchTable(t *testing.T) {
	got := MethodTools()
	if len(got) != len(grpcMethodToMCPToolMap) {
		t.Fatalf("MethodTools has %d entries, dispatch table has %d", len(got), len(grpcMethodToMCPToolMap))
	}
	for method, tool := range grpcMethodToMCPToolMap {
		if got[method] != tool {
			t.Errorf("MethodTools[%s] = %q, dispatch table has %q", method, got[method], tool)
		}
	}
	// Entries registered by init() in other files are part of the table too.
	if got[platformv1.IDevIDService_CreateLDevID_FullMethodName] != "idevid_create_ldevid" {
		t.Errorf("MethodTools is missing the init-registered LDevID mapping")
	}
}

func TestMethodTools_ReturnsCopy(t *testing.T) {
	method := platformv1.IDevIDService_CreateLDevID_FullMethodName
	got := MethodTools()
	got[method] = "tampered"
	delete(got, platformv1.AttestationService_GetDeviceReport_FullMethodName)

	if grpcMethodToMCPToolMap[method] != "idevid_create_ldevid" {
		t.Errorf("mutating the returned map changed the dispatch table: %q", grpcMethodToMCPToolMap[method])
	}
	if _, ok := grpcMethodToMCPToolMap[platformv1.AttestationService_GetDeviceReport_FullMethodName]; !ok {
		t.Error("deleting from the returned map removed a dispatch table entry")
	}
}

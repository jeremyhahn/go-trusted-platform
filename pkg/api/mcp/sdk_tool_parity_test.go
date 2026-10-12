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
	"sort"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)

// TestSDKMethodTools_EveryMappedToolIsRegistered pins the SDK MCP transport's
// gRPC-method to tool-name table against this registry — the kms_sign bug
// class, where a tool is mapped on one side only and every call to it fails
// with "unknown tool". The SDK cannot import this package, so the check
// lives here.
func TestSDKMethodTools_EveryMappedToolIsRegistered(t *testing.T) {
	mapped := sdkmcp.MethodTools()
	if len(mapped) == 0 {
		t.Fatal("the SDK MCP transport maps no methods; the table did not load")
	}

	for _, m := range unregisteredSDKTools(mapped, registeredToolNames(t)) {
		t.Errorf("SDK maps %s but the server does not register that tool", m)
	}
}

// TestSDKMethodTools_UnregisteredToolIsDetected proves the check above can
// fail: a mapping to a tool the server never registers is reported, and a
// mapping to a registered tool is not.
func TestSDKMethodTools_UnregisteredToolIsDetected(t *testing.T) {
	mapped := map[string]string{
		"/platform.v1.DeviceService/DeleteDevice":     "device_delete",
		"/platform.v1.ComputeService/DeleteContainer": "no_such_tool_840",
	}

	got := unregisteredSDKTools(mapped, registeredToolNames(t))
	want := "/platform.v1.ComputeService/DeleteContainer -> no_such_tool_840"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("unregisteredSDKTools = %v, want [%s]", got, want)
	}
}

// unregisteredSDKTools returns the "method -> tool" pairs whose tool is not
// in registered, sorted for stable output.
func unregisteredSDKTools(mapped map[string]string, registered map[string]bool) []string {
	var missing []string
	for method, tool := range mapped {
		if !registered[tool] {
			missing = append(missing, method+" -> "+tool)
		}
	}
	sort.Strings(missing)
	return missing
}

func registeredToolNames(t *testing.T) map[string]bool {
	t.Helper()
	registry := NewToolRegistry(nil, logging.DefaultLogger())
	registered := map[string]bool{}
	for _, td := range registry.ListTools() {
		registered[td.Name] = true
	}
	if len(registered) == 0 {
		t.Fatal("the tool registry lists no tools")
	}
	return registered
}

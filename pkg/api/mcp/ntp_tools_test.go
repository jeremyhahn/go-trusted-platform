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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// ntpToolNames are the tools the time-synchronization surface registers.
var ntpToolNames = []string{"ntp_status", "ntp_sources", "ntp_step"}

func TestNTPToolsAreRegisteredWithSchemas(t *testing.T) {
	registry := NewToolRegistry(&mockServiceProvider{}, nil)

	tools := registry.ListTools()
	byName := make(map[string]mcpwire.ToolDefinition, len(tools))
	for _, tool := range tools {
		byName[tool.Name] = tool
	}

	for _, name := range ntpToolNames {
		tool, ok := byName[name]
		if !ok {
			t.Fatalf("tool %q is not registered", name)
		}
		if tool.Description == "" {
			t.Fatalf("tool %q has no description", name)
		}
		if tool.InputSchema["type"] != "object" {
			t.Fatalf("tool %q schema = %v, want an object", name, tool.InputSchema)
		}
	}
}

func TestNTPToolsExecuteAgainstTheProvider(t *testing.T) {
	provider := &mockServiceProvider{}
	registry := NewToolRegistry(provider, nil)
	ctx := context.Background()

	statusResult, err := registry.ExecuteTool(ctx, "ntp_status", nil)
	if err != nil {
		t.Fatalf("ntp_status error = %v", err)
	}
	statusMap, ok := statusResult.(map[string]interface{})
	if !ok {
		t.Fatalf("ntp_status result = %T, want a JSON object", statusResult)
	}
	if statusMap["synced"] != true {
		t.Fatalf("ntp_status result = %v, want synced", statusMap)
	}

	if _, err := registry.ExecuteTool(ctx, "ntp_sources", nil); err != nil {
		t.Fatalf("ntp_sources error = %v", err)
	}

	if _, err := registry.ExecuteTool(ctx, "ntp_step", nil); err != nil {
		t.Fatalf("ntp_step error = %v", err)
	}
	if provider.ntpStepCalls != 1 {
		t.Fatalf("ntp_step calls = %d, want 1", provider.ntpStepCalls)
	}
}

func TestNTPToolsPropagateProviderFailures(t *testing.T) {
	provider := &mockServiceProvider{ntpErr: errors.New("chrony control socket unavailable")}
	registry := NewToolRegistry(provider, nil)
	ctx := context.Background()

	for _, name := range ntpToolNames {
		t.Run(name, func(t *testing.T) {
			if _, err := registry.ExecuteTool(ctx, name, nil); err == nil {
				t.Fatalf("%s = nil error, want the provider failure", name)
			}
		})
	}
}

func TestNTPToolDispatchIgnoresForeignToolNames(t *testing.T) {
	registry := NewToolRegistry(&mockServiceProvider{}, nil)

	result, handled, err := registry.dispatchNTPTool(context.Background(), "gateway_perf_flows")
	if handled {
		t.Fatalf("dispatchNTPTool claimed a foreign tool (result %v)", result)
	}
	if err != nil {
		t.Fatalf("err = %v, want nil for an unhandled tool", err)
	}
}

func TestNTPToolPermissionsGateWritesSeparatelyFromReads(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	wants := map[string]string{
		"ntp_status":  "ntp:read",
		"ntp_sources": "ntp:read",
		"ntp_step":    "ntp:write",
	}
	for tool, want := range wants {
		if got := checker.toolPermissions[tool]; got != want {
			t.Fatalf("permission for %s = %q, want %q", tool, got, want)
		}
	}
}

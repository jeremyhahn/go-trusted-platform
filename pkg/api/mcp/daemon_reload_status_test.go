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
	"encoding/json"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDaemonReloadConfigTool_ResultDecodesAsReloadConfigResponse verifies
// the platform_daemon_reload_config result carries the protobuf status
// object, so the SDK MCP adapter's JSON round-trip into
// platformv1.ReloadConfigResponse keeps success and message (Codex round 3,
// #1852). The provider answers with the flattened shape it builds from
// Service.ReloadConfig.
func TestDaemonReloadConfigTool_ResultDecodesAsReloadConfigResponse(t *testing.T) {
	svc := newMockServiceProvider()
	svc.daemonReloadConfigFunc = func(ctx context.Context) (interface{}, error) {
		return map[string]interface{}{
			"success":           true,
			"message":           "reloaded",
			"reloaded_sections": []string{"logging"},
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.ExecuteTool(context.Background(), "platform_daemon_reload_config", map[string]interface{}{})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var resp platformv1.ReloadConfigResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode as ReloadConfigResponse: %v", err)
	}
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "reloaded" {
		t.Errorf("status = %+v, want success with message %q (result %s)", resp.GetStatus(), "reloaded", data)
	}
	if got := resp.GetReloadedSections(); len(got) != 1 || got[0] != "logging" {
		t.Errorf("reloaded_sections = %v, want [logging]", got)
	}
}

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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestPlatformDaemon_GetConfig_ThroughAdapter drives the generated
// PlatformDaemon client over the MCP transport: GetConfig must reach
// platform_daemon_get_config with its section argument.
func TestPlatformDaemon_GetConfig_ThroughAdapter(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_daemon_get_config": map[string]interface{}{
			"sections": []interface{}{
				map[string]interface{}{"section": "luks", "values": map[string]interface{}{"enabled": "true"}},
			},
		},
	}, &calls)

	client := platformv1.NewPlatformDaemonClient(a.Connection())
	resp, err := client.GetConfig(context.Background(), &platformv1.GetConfigRequest{Section: "luks"})
	if err != nil {
		t.Fatalf("GetConfig over MCP: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_daemon_get_config" {
		t.Fatalf("calls = %+v, want a single platform_daemon_get_config", calls)
	}
	if got := calls[0].Arguments["section"]; got != "luks" {
		t.Errorf("section argument = %v, want luks", got)
	}
	if len(resp.GetSections()) != 1 || resp.GetSections()[0].GetValues()["enabled"] != "true" {
		t.Errorf("sections = %+v, want the luks section", resp.GetSections())
	}
}

// TestPlatformDaemon_ReloadConfig_ThroughAdapter drives ReloadConfig over the
// MCP transport to platform_daemon_reload_config and decodes its status.
func TestPlatformDaemon_ReloadConfig_ThroughAdapter(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_daemon_reload_config": map[string]interface{}{
			"status":            map[string]interface{}{"success": true, "message": "reloaded"},
			"reloaded_sections": []interface{}{"luks"},
		},
	}, &calls)

	client := platformv1.NewPlatformDaemonClient(a.Connection())
	resp, err := client.ReloadConfig(context.Background(), &platformv1.ReloadConfigRequest{})
	if err != nil {
		t.Fatalf("ReloadConfig over MCP: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_daemon_reload_config" {
		t.Fatalf("calls = %+v, want a single platform_daemon_reload_config", calls)
	}
	if !resp.GetStatus().GetSuccess() {
		t.Errorf("status = %+v, want success", resp.GetStatus())
	}
	if got := resp.GetReloadedSections(); len(got) != 1 || got[0] != "luks" {
		t.Errorf("reloaded sections = %v, want [luks]", got)
	}
}

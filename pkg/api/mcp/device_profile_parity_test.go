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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const testTLSServerName = "compute.trusted-platform.internal"

// TestDeviceProfileSchemas_TLSServerName pins that both profile write tools
// advertise tls_server_name and that neither advertises pcr_baseline, which
// is read-only (#448).
func TestDeviceProfileSchemas_TLSServerName(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	for _, toolName := range []string{"profile_create", "profile_update_by_id"} {
		var schema map[string]interface{}
		for _, tool := range registry.ListTools() {
			if tool.Name == toolName {
				schema = tool.InputSchema
			}
		}
		if schema == nil {
			t.Fatalf("tool %q not registered", toolName)
		}
		properties := schema["properties"].(map[string]interface{})
		if _, ok := properties["tls_server_name"]; !ok {
			t.Errorf("tool %q schema missing tls_server_name", toolName)
		}
		if _, ok := properties["pcr_baseline"]; ok {
			t.Errorf("tool %q must not advertise the read-only pcr_baseline as settable", toolName)
		}
	}
}

// TestDeviceProfileCreateUpdate_TLSServerName is the MCP round trip: create
// with the name, get, update without it, get again, then replace it.
func TestDeviceProfileCreateUpdate_TLSServerName(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	ctx := context.Background()

	created, err := registry.ExecuteTool(ctx, "profile_create", map[string]interface{}{
		"name": "compute", "role": "worker", "tls_server_name": testTLSServerName,
	})
	if err != nil {
		t.Fatalf("profile_create: %v", err)
	}
	obj := created.(map[string]interface{})
	if obj["tls_server_name"] != testTLSServerName {
		t.Fatalf("create result lacks tls_server_name: %v", obj)
	}
	var id uint64
	for k := range stub.profiles {
		id = k
	}
	if stub.profiles[id].TLSServerName != testTLSServerName {
		t.Fatal("stored profile lacks TLSServerName")
	}

	updated, err := registry.ExecuteTool(ctx, "profile_update_by_id", map[string]interface{}{"id": id, "model": "X10SDV"})
	if err != nil {
		t.Fatalf("profile_update_by_id: %v", err)
	}
	if updated.(map[string]interface{})["tls_server_name"] != testTLSServerName {
		t.Fatal("an update that omits tls_server_name must not erase it")
	}
	if stub.profiles[id].TLSServerName != testTLSServerName || stub.profiles[id].Model != "X10SDV" {
		t.Fatalf("stored profile after partial update: %+v", stub.profiles[id])
	}

	if _, err := registry.ExecuteTool(ctx, "profile_update_by_id", map[string]interface{}{"id": id, "tls_server_name": "gw.trusted-platform.internal"}); err != nil {
		t.Fatalf("profile_update_by_id (replace): %v", err)
	}
	if stub.profiles[id].TLSServerName != "gw.trusted-platform.internal" {
		t.Fatal("a caller that names tls_server_name must win")
	}
}

// TestDeviceProfileTools_PCRBaselineReadOnly pins that pcr_baseline in the
// arguments never reaches the entity on create or update, while results
// report the baseline the verifier recorded in the domain JSON shape.
func TestDeviceProfileTools_PCRBaselineReadOnly(t *testing.T) {
	registry, stub := newDeviceProfileRegistry()
	ctx := context.Background()
	supplied := map[string]interface{}{"values": map[string]string{"0": "7g=="}, "source": "signed", "recorded_at": "2026-09-01T12:00:00Z"}

	created, err := registry.ExecuteTool(ctx, "profile_create", map[string]interface{}{
		"name": "workers", "role": "worker", "pcr_baseline": supplied,
	})
	if err != nil {
		t.Fatalf("profile_create: %v", err)
	}
	if _, present := created.(map[string]interface{})["pcr_baseline"]; present {
		t.Fatal("a caller-supplied baseline must not be stored or echoed")
	}
	var id uint64
	for k := range stub.profiles {
		id = k
	}
	if stub.profiles[id].PCRBaseline != nil {
		t.Fatal("a caller-supplied baseline reached the entity")
	}

	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	stub.profiles[id].PCRBaseline = &entities.PCRBaseline{
		Values: map[int][]byte{7: {0xbb}}, Source: entities.BaselineSourceTOFU, RecordedAt: recorded, RecordedFromDeviceID: 77,
	}
	updated, err := registry.ExecuteTool(ctx, "profile_update_by_id", map[string]interface{}{"id": id, "model": "X10SDV", "pcr_baseline": supplied})
	if err != nil {
		t.Fatalf("profile_update_by_id: %v", err)
	}
	baseline, ok := updated.(map[string]interface{})["pcr_baseline"].(map[string]interface{})
	if !ok {
		t.Fatalf("result must report the recorded baseline: %v", updated)
	}
	if baseline["source"] != "tofu" {
		t.Fatalf("a caller-supplied baseline must not replace the recorded one: %v", baseline)
	}
	if stub.profiles[id].PCRBaseline.Source != entities.BaselineSourceTOFU {
		t.Fatal("stored baseline was replaced by the caller's")
	}

	got, err := registry.ExecuteTool(ctx, "profile_get_by_id", map[string]interface{}{"id": id})
	if err != nil {
		t.Fatalf("profile_get_by_id: %v", err)
	}
	if got.(map[string]interface{})["pcr_baseline"].(map[string]interface{})["source"] != "tofu" {
		t.Fatal("get must report the recorded baseline")
	}
}

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

package registry

import (
	"encoding/json"
	"testing"

	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// decodeStatusDocument converts a domain status and decodes the printed
// JSON document.
func decodeStatusDocument(t *testing.T, resp *regsvc.RegistryStatusResult) map[string]any {
	t.Helper()
	out, err := json.Marshal(convertStatusDomainResponse(resp))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

// TestStatusDocument_HealthyIsFlatWithBackend checks the flat document of
// docs/registry/cli.md §7, including the storage backend detail.
func TestStatusDocument_HealthyIsFlatWithBackend(t *testing.T) {
	doc := decodeStatusDocument(t, &regsvc.RegistryStatusResult{
		Health:    regsvc.HealthStatusHealthy,
		Version:   "1.2.3",
		StartedAt: 100,
		Timestamp: 160,
		Storage:   &regsvc.StorageStats{UsedBytes: 4096, ArtifactCount: 3},
		Components: []*regsvc.ComponentStatus{{
			Name:    "storage",
			Status:  regsvc.HealthStatusHealthy,
			Details: map[string]string{"backend": "filesystem"},
		}},
	})

	want := map[string]any{
		"healthy":         true,
		"status":          "running",
		"version":         "1.2.3",
		"uptime_seconds":  float64(60),
		"image_count":     float64(3),
		"total_size":      float64(4096),
		"storage_backend": "filesystem",
	}
	for key, value := range want {
		if doc[key] != value {
			t.Errorf("%s = %v, want %v", key, doc[key], value)
		}
	}
}

// TestStatusDocument_UnhealthyIsDegraded checks that an unhealthy registry
// prints degraded and no backend it was not told about.
func TestStatusDocument_UnhealthyIsDegraded(t *testing.T) {
	doc := decodeStatusDocument(t, &regsvc.RegistryStatusResult{Health: regsvc.HealthStatusUnhealthy})

	if doc["status"] != "degraded" {
		t.Errorf("status = %v, want degraded", doc["status"])
	}
	if doc["healthy"] != false {
		t.Errorf("healthy = %v, want false", doc["healthy"])
	}
	if _, ok := doc["storage_backend"]; ok {
		t.Errorf("storage_backend present without a storage component")
	}
}

// TestStatusDocument_NilStatus checks that an empty result still prints a
// valid degraded document.
func TestStatusDocument_NilStatus(t *testing.T) {
	out, err := json.Marshal(&StatusResult{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["status"] != "degraded" {
		t.Errorf("status = %v, want degraded", doc["status"])
	}
}

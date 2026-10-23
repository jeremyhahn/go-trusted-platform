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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestStatusResultFromProto_CarriesComponentDetails(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Health:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Version: "1.2.3",
		Components: []*platformv1.ComponentHealth{{
			Name:    "storage",
			Status:  platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			Details: map[string]string{"backend": "quicbaas"},
		}},
	}

	result := StatusResultFromProto(resp)

	if len(result.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(result.Components))
	}
	component := result.Components[0]
	if component.Name != "storage" || component.Status != HealthStatusHealthy {
		t.Fatalf("component = %+v, want healthy storage", component)
	}
	if got := component.Details["backend"]; got != "quicbaas" {
		t.Fatalf("backend detail = %q, want %q", got, "quicbaas")
	}
}

func TestStatusResultFromProto_NilAndDetailless(t *testing.T) {
	if result := StatusResultFromProto(nil); result != nil {
		t.Fatalf("nil response converted to %+v, want nil", result)
	}

	result := StatusResultFromProto(&platformv1.RegistryStatusResponse{
		Components: []*platformv1.ComponentHealth{{Name: "storage"}},
	})
	if details := result.Components[0].Details; len(details) != 0 {
		t.Fatalf("details = %v, want none", details)
	}
}

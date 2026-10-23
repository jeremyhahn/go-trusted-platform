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

// TestStatusResultFromProto_KeepsComponentDetails checks that a component's
// details, where the server puts the storage backend, survive conversion.
func TestStatusResultFromProto_KeepsComponentDetails(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Components: []*platformv1.ComponentHealth{
			{Name: "storage", Details: map[string]string{"backend": "filesystem"}},
		},
	}

	result := StatusResultFromProto(resp)

	if len(result.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(result.Components))
	}
	if got := result.Components[0].Details["backend"]; got != "filesystem" {
		t.Errorf("backend detail = %q, want filesystem", got)
	}
}

// TestStatusResultFromProto_ComponentWithoutDetails checks that a component
// without details converts with no details.
func TestStatusResultFromProto_ComponentWithoutDetails(t *testing.T) {
	resp := &platformv1.RegistryStatusResponse{
		Components: []*platformv1.ComponentHealth{{Name: "attestation"}},
	}

	result := StatusResultFromProto(resp)

	if len(result.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(result.Components))
	}
	if len(result.Components[0].Details) != 0 {
		t.Errorf("details = %v, want none", result.Components[0].Details)
	}
}

// TestStatusResultFromProto_Nil checks that a nil response converts to nil.
func TestStatusResultFromProto_Nil(t *testing.T) {
	if result := StatusResultFromProto(nil); result != nil {
		t.Fatalf("nil response converted to %+v, want nil", result)
	}
}

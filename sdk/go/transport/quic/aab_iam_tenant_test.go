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

package quic

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// iamTenantMethodSubs lists every PlatformIAMService tenant method with the
// sub-opcode the daemon's IAM category expects for it.
var iamTenantMethodSubs = map[string]byte{
	platformv1.PlatformIAMService_CreateTenant_FullMethodName: quicwire.IAMSubTenantCreate,
	platformv1.PlatformIAMService_GetTenant_FullMethodName:    quicwire.IAMSubTenantGet,
	platformv1.PlatformIAMService_ListTenants_FullMethodName:  quicwire.IAMSubTenantList,
	platformv1.PlatformIAMService_UpdateTenant_FullMethodName: quicwire.IAMSubTenantUpdate,
	platformv1.PlatformIAMService_DeleteTenant_FullMethodName: quicwire.IAMSubTenantDelete,
}

// TestIAMTenantMethodsAvoidPlatformTenancyOpcodes guards #767: the OpTenant*
// bytes dispatch to the platform TenantService (quotas, DEKs, sync), so an
// IAM tenant call routed onto them would reach the wrong service under the
// wrong scope.
func TestIAMTenantMethodsAvoidPlatformTenancyOpcodes(t *testing.T) {
	for method := range iamTenantMethodSubs {
		t.Run(method, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no opcode mapping", method)
			}
			if quicwire.IsTenantOpcode(opcode) {
				t.Fatalf("%s maps to platform tenancy opcode 0x%02x", method, opcode)
			}
		})
	}
}

// TestIAMTenantMethodsRouteToIAMCategory pins each IAM tenant method to the
// IAM category and the sub-opcode the daemon dispatches on.
func TestIAMTenantMethodsRouteToIAMCategory(t *testing.T) {
	for method, wantSub := range iamTenantMethodSubs {
		t.Run(method, func(t *testing.T) {
			if opcode := grpcMethodToOpcodeMap[method]; opcode != quicwire.OpIAMCategory {
				t.Fatalf("opcode = 0x%02x, want OpIAMCategory 0x%02x", opcode, quicwire.OpIAMCategory)
			}
			sub, ok := categorySubOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no sub-opcode mapping", method)
			}
			if sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x, want 0x%02x", sub, wantSub)
			}
			if _, empty := categoryEmptyBodyMethods[method]; empty {
				t.Fatalf("%s is marked empty-bodied, but its request carries the tenant fields", method)
			}
		})
	}
}

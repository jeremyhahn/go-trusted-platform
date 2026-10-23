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

// TestInvitationMethodsRouteToTheIAMCategory pins the QUIC wire contract for
// every method the generated InvitationService descriptor declares. A missing
// entry means the transport silently answers Unimplemented.
func TestInvitationMethodsRouteToTheIAMCategory(t *testing.T) {
	for _, desc := range platformv1.InvitationService_ServiceDesc.Methods {
		method := "/" + platformv1.InvitationService_ServiceDesc.ServiceName + "/" + desc.MethodName
		t.Run(desc.MethodName, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no opcode mapping", method)
			}
			if opcode != quicwire.OpIAMCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpIAMCategory)
			}
			if _, ok := categorySubOpcodeMap[method]; !ok {
				t.Fatalf("%s has no sub-opcode mapping", method)
			}
		})
	}
}

// TestInvitationSubOpcodesAreDistinctWithinTheIAMCategory guards against a
// collision with another invitation method or with an IAM tenant-record
// method, either of which would route two methods to one daemon handler.
func TestInvitationSubOpcodesAreDistinctWithinTheIAMCategory(t *testing.T) {
	seen := make(map[byte]string, len(invitationSubOpcodes)+len(iamTenantSubOpcodes))
	for _, subs := range []map[string]byte{iamTenantSubOpcodes, invitationSubOpcodes} {
		for method, sub := range subs {
			if other, clash := seen[sub]; clash {
				t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
			}
			seen[sub] = method
		}
	}
}

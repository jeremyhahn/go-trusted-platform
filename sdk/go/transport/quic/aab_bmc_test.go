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

// TestBMCMethodsRouteToTheCategoryOpcode pins the QUIC wire contract for
// every method the generated BMCService descriptor declares. A missing entry
// means the transport silently answers Unimplemented.
func TestBMCMethodsRouteToTheCategoryOpcode(t *testing.T) {
	if _, isCategory := categoryOpcodes[quicwire.OpBMCCategory]; !isCategory {
		t.Fatal("OpBMCCategory is not registered as a category opcode")
	}

	for _, desc := range platformv1.BMCService_ServiceDesc.Methods {
		method := "/" + platformv1.BMCService_ServiceDesc.ServiceName + "/" + desc.MethodName
		t.Run(desc.MethodName, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no opcode mapping", method)
			}
			if opcode != quicwire.OpBMCCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpBMCCategory)
			}
			if _, ok := categorySubOpcodeMap[method]; !ok {
				t.Fatalf("%s has no sub-opcode mapping", method)
			}
		})
	}
}

// TestBMCSubOpcodesAreDistinct guards against a copy-paste collision that
// would route two methods to the same daemon handler.
func TestBMCSubOpcodesAreDistinct(t *testing.T) {
	seen := make(map[byte]string, len(bmcSubOpcodes))
	for method, sub := range bmcSubOpcodes {
		if other, clash := seen[sub]; clash {
			t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
		}
		seen[sub] = method
	}
}

// TestBMCCategoryPayloadCarriesTheSubOpcode verifies the adapter prefixes the
// encoded request with the method's sub-opcode byte.
func TestBMCCategoryPayloadCarriesTheSubOpcode(t *testing.T) {
	payload, err := buildCategoryPayload(quicwire.BMCSubPowerStatus, &platformv1.BMCPowerStatusRequest{ProfileId: 7})
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if len(payload) < 2 || payload[0] != quicwire.BMCSubPowerStatus {
		t.Fatalf("payload = %v, want sub-opcode 0x%02x then the request", payload, quicwire.BMCSubPowerStatus)
	}

	var decoded platformv1.BMCPowerStatusRequest
	if err := quicwire.DecodePayload(payload[1:], &decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.GetProfileId() != 7 {
		t.Fatalf("profile id = %d, want 7", decoded.GetProfileId())
	}
}

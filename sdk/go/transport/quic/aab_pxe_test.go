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

// TestPXEMethodsAreMapped pins the QUIC wire contract for every method the
// generated PXEService descriptor declares: a direct opcode, or the
// provisioning category with a sub-opcode. A missing entry means the
// transport silently answers Unimplemented.
func TestPXEMethodsAreMapped(t *testing.T) {
	for _, desc := range platformv1.PXEService_ServiceDesc.Methods {
		method := "/" + platformv1.PXEService_ServiceDesc.ServiceName + "/" + desc.MethodName
		t.Run(desc.MethodName, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no opcode mapping", method)
			}
			if direct, isDirect := pxeDirectOpcodes[method]; isDirect {
				if opcode != direct {
					t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, direct)
				}
				return
			}
			if opcode != quicwire.OpProvisioningCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpProvisioningCategory)
			}
			if sub, ok := categorySubOpcodeMap[method]; !ok || sub != pxeSubOpcodes[method] {
				t.Fatalf("%s sub-opcode = 0x%02x (mapped %v), want 0x%02x", method, sub, ok, pxeSubOpcodes[method])
			}
		})
	}
}

// TestPXEMappingCoversOnlyPXEServiceMethods guards against a mapping entry
// for a method the descriptor does not declare, which would never be called.
func TestPXEMappingCoversOnlyPXEServiceMethods(t *testing.T) {
	declared := make(map[string]struct{}, len(platformv1.PXEService_ServiceDesc.Methods))
	for _, desc := range platformv1.PXEService_ServiceDesc.Methods {
		declared["/"+platformv1.PXEService_ServiceDesc.ServiceName+"/"+desc.MethodName] = struct{}{}
	}
	if got, want := len(pxeDirectOpcodes)+len(pxeSubOpcodes), len(declared); got != want {
		t.Fatalf("mapped %d PXE methods, descriptor declares %d", got, want)
	}
	for _, table := range []map[string]byte{pxeDirectOpcodes, pxeSubOpcodes} {
		for method := range table {
			if _, ok := declared[method]; !ok {
				t.Errorf("%s is mapped but PXEService does not declare it", method)
			}
		}
	}
}

// TestProvisioningCategorySubOpcodesAreDistinct guards the shared 0xCF
// sub-opcode space: provisioning, EAB, device profile and PXE methods all
// multiplex there, and a collision routes two methods to one daemon handler.
func TestProvisioningCategorySubOpcodesAreDistinct(t *testing.T) {
	seen := make(map[byte]string)
	for method, opcode := range grpcMethodToOpcodeMap {
		if opcode != quicwire.OpProvisioningCategory {
			continue
		}
		sub := categorySubOpcodeMap[method]
		if other, clash := seen[sub]; clash {
			t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
		}
		seen[sub] = method
	}
	for _, sub := range pxeSubOpcodes {
		if _, ok := seen[sub]; !ok {
			t.Fatalf("PXE sub-opcode 0x%02x is not routed under the provisioning category", sub)
		}
	}
}

// TestPXECategoryPayloadCarriesTheSubOpcode verifies the adapter prefixes the
// encoded request with the method's sub-opcode byte.
func TestPXECategoryPayloadCarriesTheSubOpcode(t *testing.T) {
	payload, err := buildCategoryPayload(quicwire.PXESubGetDeviceByMAC, &platformv1.GetPXEDeviceByMACRequest{MacAddress: "aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if len(payload) < 2 || payload[0] != quicwire.PXESubGetDeviceByMAC {
		t.Fatalf("payload = %v, want sub-opcode 0x%02x then the request", payload, quicwire.PXESubGetDeviceByMAC)
	}

	var decoded platformv1.GetPXEDeviceByMACRequest
	if err := quicwire.DecodePayload(payload[1:], &decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.GetMacAddress() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("mac = %q, want aa:bb:cc:dd:ee:ff", decoded.GetMacAddress())
	}
}

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

// vpnMethods enumerates every VPNService method with its expected sub-opcode.
var vpnMethods = map[string]byte{
	platformv1.VPNService_EnrolPeer_FullMethodName:           quicwire.VPNSubEnrolPeer,
	platformv1.VPNService_ListPeers_FullMethodName:           quicwire.VPNSubListPeers,
	platformv1.VPNService_RevokePeer_FullMethodName:          quicwire.VPNSubRevokePeer,
	platformv1.VPNService_GetStatus_FullMethodName:           quicwire.VPNSubGetStatus,
	platformv1.VPNService_GetPosturePolicy_FullMethodName:    quicwire.VPNSubGetPosturePolicy,
	platformv1.VPNService_SetPosturePolicy_FullMethodName:    quicwire.VPNSubSetPosturePolicy,
	platformv1.VPNService_DeletePosturePolicy_FullMethodName: quicwire.VPNSubDeletePosturePolicy,
	platformv1.VPNService_ListPosturePolicies_FullMethodName: quicwire.VPNSubListPosturePolicies,
}

// TestVPNMethodsRouteToTheCategoryOpcode pins the QUIC wire contract: every
// VPNService method reaches OpVPNCategory with its own sub-opcode and carries
// its request body.
func TestVPNMethodsRouteToTheCategoryOpcode(t *testing.T) {
	if _, isCategory := categoryOpcodes[quicwire.OpVPNCategory]; !isCategory {
		t.Fatal("OpVPNCategory is not registered as a category opcode")
	}
	if len(platformv1.VPNService_ServiceDesc.Methods) != len(vpnMethods) {
		t.Fatalf("VPNService has %d methods, the wire table pins %d", len(platformv1.VPNService_ServiceDesc.Methods), len(vpnMethods))
	}

	for method, wantSub := range vpnMethods {
		t.Run(method, func(t *testing.T) {
			if opcode := grpcMethodToOpcodeMap[method]; opcode != quicwire.OpVPNCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpVPNCategory)
			}
			if sub, ok := categorySubOpcodeMap[method]; !ok || sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x (mapped %t), want 0x%02x", sub, ok, wantSub)
			}
			if _, empty := categoryEmptyBodyMethods[method]; empty {
				t.Fatalf("%s carries a request body and must not be marked empty-bodied", method)
			}
		})
	}
}

// TestVPNCategoryPayloadCarriesTheRequest verifies the bytes on the wire: the
// sub-opcode, then the encoded request the daemon decodes.
func TestVPNCategoryPayloadCarriesTheRequest(t *testing.T) {
	request := &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"}
	payload, err := buildCategoryPayload(quicwire.VPNSubRevokePeer, request)
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if payload[0] != quicwire.VPNSubRevokePeer {
		t.Fatalf("payload[0] = 0x%02x, want 0x%02x", payload[0], quicwire.VPNSubRevokePeer)
	}

	var decoded platformv1.RevokeVPNPeerRequest
	if err := quicwire.DecodePayload(payload[1:], &decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.GetTenantId() != "acme" || decoded.GetDeviceId() != "laptop-1" {
		t.Fatalf("decoded = %v, want the original request", &decoded)
	}
}

// TestVPNSubOpcodesAreDistinct guards against a copy-paste collision that
// would route two operations to the same handler.
func TestVPNSubOpcodesAreDistinct(t *testing.T) {
	seen := make(map[byte]string, len(vpnMethods))
	for method, sub := range vpnMethods {
		if other, clash := seen[sub]; clash {
			t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
		}
		seen[sub] = method
	}
}

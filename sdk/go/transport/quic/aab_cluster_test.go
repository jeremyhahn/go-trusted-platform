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

// TestClusterMethodsRouteToTheCategoryOpcode pins the QUIC wire contract for
// every method the generated ClusterService descriptor declares. A missing
// entry means the transport silently answers Unimplemented.
func TestClusterMethodsRouteToTheCategoryOpcode(t *testing.T) {
	if _, isCategory := categoryOpcodes[quicwire.OpClusterCategory]; !isCategory {
		t.Fatal("OpClusterCategory is not registered as a category opcode")
	}

	for _, desc := range platformv1.ClusterService_ServiceDesc.Methods {
		method := "/" + platformv1.ClusterService_ServiceDesc.ServiceName + "/" + desc.MethodName
		t.Run(desc.MethodName, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no opcode mapping", method)
			}
			if opcode != quicwire.OpClusterCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpClusterCategory)
			}
			if _, ok := categorySubOpcodeMap[method]; !ok {
				t.Fatalf("%s has no sub-opcode mapping", method)
			}
		})
	}
}

// TestClusterSubOpcodesAreDistinct guards against a copy-paste collision that
// would route two methods to the same daemon handler.
func TestClusterSubOpcodesAreDistinct(t *testing.T) {
	seen := make(map[byte]string, len(clusterSubOpcodes))
	for method, sub := range clusterSubOpcodes {
		if other, clash := seen[sub]; clash {
			t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
		}
		seen[sub] = method
	}
}

// TestClusterCategoryPayloadCarriesTheSubOpcode verifies the adapter prefixes
// the encoded request with the method's sub-opcode byte.
func TestClusterCategoryPayloadCarriesTheSubOpcode(t *testing.T) {
	request := &platformv1.JoinClusterRequest{NodeName: "node-2", SeedAddresses: []string{"10.0.0.1:7000"}}
	payload, err := buildCategoryPayload(quicwire.ClusterSubJoin, request)
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if len(payload) < 2 || payload[0] != quicwire.ClusterSubJoin {
		t.Fatalf("payload = %v, want sub-opcode 0x%02x then the request", payload, quicwire.ClusterSubJoin)
	}

	var decoded platformv1.JoinClusterRequest
	if err := quicwire.DecodePayload(payload[1:], &decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.GetNodeName() != "node-2" || len(decoded.GetSeedAddresses()) != 1 {
		t.Fatalf("decoded = %+v, want node-2 with one seed", &decoded)
	}
}

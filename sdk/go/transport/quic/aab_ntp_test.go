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

// ntpMethods enumerates every NTPService method with its expected sub-opcode.
var ntpMethods = map[string]byte{
	platformv1.NTPService_GetStatus_FullMethodName:   quicwire.NTPSubGetStatus,
	platformv1.NTPService_ListSources_FullMethodName: quicwire.NTPSubListSources,
	platformv1.NTPService_Step_FullMethodName:        quicwire.NTPSubStep,
}

// TestNTPMethodsRouteToTheCategoryOpcode pins the QUIC wire contract. A
// missing entry here means the transport silently answers Unimplemented, and
// a wrong sub-opcode means the daemon dispatches the wrong operation.
func TestNTPMethodsRouteToTheCategoryOpcode(t *testing.T) {
	if _, isCategory := categoryOpcodes[quicwire.OpNTPCategory]; !isCategory {
		t.Fatal("OpNTPCategory is not registered as a category opcode")
	}

	for method, wantSub := range ntpMethods {
		t.Run(method, func(t *testing.T) {
			opcode, ok := grpcMethodToOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no opcode mapping", method)
			}
			if opcode != quicwire.OpNTPCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpNTPCategory)
			}

			sub, ok := categorySubOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no sub-opcode mapping", method)
			}
			if sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x, want 0x%02x", sub, wantSub)
			}

			// Every NTP request is an empty message: the adapter must
			// send only the sub-opcode byte, matching the daemon
			// dispatcher which tolerates a zero-length sub-payload.
			if _, empty := categoryEmptyBodyMethods[method]; !empty {
				t.Fatalf("%s must be marked empty-bodied", method)
			}
		})
	}
}

// TestNTPCategoryPayloadCarriesOnlyTheSubOpcode verifies the exact bytes the
// adapter puts on the wire for an empty-bodied NTP call.
func TestNTPCategoryPayloadCarriesOnlyTheSubOpcode(t *testing.T) {
	payload, err := buildCategoryPayload(quicwire.NTPSubGetStatus, nil)
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if len(payload) != 1 || payload[0] != quicwire.NTPSubGetStatus {
		t.Fatalf("payload = %v, want [0x%02x]", payload, quicwire.NTPSubGetStatus)
	}
}

// TestNTPSubOpcodesAreDistinct guards against a copy-paste collision that
// would route two operations to the same handler.
func TestNTPSubOpcodesAreDistinct(t *testing.T) {
	seen := make(map[byte]string, len(ntpMethods))
	for method, sub := range ntpMethods {
		if other, clash := seen[sub]; clash {
			t.Fatalf("sub-opcode 0x%02x is shared by %s and %s", sub, other, method)
		}
		seen[sub] = method
	}
}

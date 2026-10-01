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

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// TestNAT64Status_ResolvesToItsCategoryAndSubOpcode pins both halves of the
// QUIC mapping. The package init() guard only fires for methods already in
// grpcMethodToOpcodeMap, so a method missing from BOTH tables slips past it
// entirely and the adapter has no opcode to send at all (#601).
func TestNAT64Status_ResolvesToItsCategoryAndSubOpcode(t *testing.T) {
	const method = "/platform.v1.GatewayService/GetNAT64Status"

	opcode, ok := grpcMethodToOpcodeMap[method]
	if !ok {
		t.Fatalf("%s has no QUIC opcode mapping; the adapter cannot dispatch it", method)
	}
	if opcode != quicapi.OpGatewayCategory {
		t.Errorf("NAT64 status opcode = %#x, want the gateway category %#x", opcode, quicapi.OpGatewayCategory)
	}

	sub, ok := categorySubOpcodeMap[method]
	if !ok {
		t.Fatalf("%s resolves to a category opcode but has no sub-opcode; a zero byte would be sent", method)
	}
	if sub != quicapi.OpGatewayNAT64Status {
		t.Errorf("NAT64 status sub-opcode = %#x, want %#x", sub, quicapi.OpGatewayNAT64Status)
	}
}

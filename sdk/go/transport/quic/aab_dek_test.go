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

	kmspb "github.com/jeremyhahn/go-quicbaas/api/proto"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestDEKMethodsRouteToTheKMSExtendedCategory pins the QUIC wire contract the
// daemon's DEK dispatcher serves.
func TestDEKMethodsRouteToTheKMSExtendedCategory(t *testing.T) {
	want := map[string]byte{
		kmspb.DEKManagement_CreateDEK_FullMethodName:    0x08,
		kmspb.DEKManagement_ListDEKs_FullMethodName:     0x09,
		kmspb.DEKManagement_GetDEK_FullMethodName:       0x0A,
		kmspb.DEKManagement_GetDEKStatus_FullMethodName: 0x0B,
		kmspb.DEKManagement_RotateDEK_FullMethodName:    0x0C,
		kmspb.DEKManagement_DeleteDEK_FullMethodName:    0x0D,
	}
	for method, wantSub := range want {
		t.Run(method, func(t *testing.T) {
			if opcode := grpcMethodToOpcodeMap[method]; opcode != quicwire.OpKMSExtendedCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpKMSExtendedCategory)
			}
			sub, ok := categorySubOpcodeMap[method]
			if !ok || sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x (mapped %v), want 0x%02x", sub, ok, wantSub)
			}
		})
	}
}

// TestDEKSubOpcodesDoNotCollide keeps the DEK subs off the key-lifecycle and
// CA subs that share OpKMSExtendedCategory.
func TestDEKSubOpcodesDoNotCollide(t *testing.T) {
	taken := map[byte]string{}
	for method, sub := range categorySubOpcodeMap {
		if grpcMethodToOpcodeMap[method] != quicwire.OpKMSExtendedCategory {
			continue
		}
		if other, dup := taken[sub]; dup {
			t.Errorf("sub-opcode 0x%02x is mapped by both %s and %s", sub, other, method)
		}
		taken[sub] = method
	}
	if len(taken) < len(dekMethodSubOpcodes) {
		t.Fatalf("%d sub-opcodes under 0xCD, want at least the %d DEK subs", len(taken), len(dekMethodSubOpcodes))
	}
}

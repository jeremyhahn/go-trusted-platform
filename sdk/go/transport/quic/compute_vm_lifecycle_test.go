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
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// vmLifecycleSubOpcodes are the VM lifecycle verbs platformd answers over
// QUIC, each a sub-opcode under OpVMExtendedCategory
// (pkg/api/daemon/quic_vm_pb.go::handleVMPB).
var vmLifecycleSubOpcodes = map[string]byte{
	platformv1.ComputeService_RebootVM_FullMethodName:  quicwire.OpVMRestart,
	platformv1.ComputeService_SuspendVM_FullMethodName: quicwire.OpVMSuspend,
	platformv1.ComputeService_ResumeVM_FullMethodName:  quicwire.OpVMResume,
}

// TestVMLifecycleMethodsRouteToTheVMCategory pins the wire contract: a
// wrong sub-opcode makes the daemon run the wrong verb on the VM.
func TestVMLifecycleMethodsRouteToTheVMCategory(t *testing.T) {
	for method, wantSub := range vmLifecycleSubOpcodes {
		t.Run(method, func(t *testing.T) {
			if opcode := grpcMethodToOpcodeMap[method]; opcode != quicwire.OpVMExtendedCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpVMExtendedCategory)
			}
			sub, ok := categorySubOpcodeMap[method]
			if !ok {
				t.Fatalf("%s has no sub-opcode mapping", method)
			}
			if sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x, want 0x%02x", sub, wantSub)
			}
		})
	}
}

// StartVM, StopVM and DeleteVM have no answer on platformd's QUIC listener,
// so the adapter refuses them locally as Unimplemented rather than sending
// a request the daemon answers Unavailable.
func TestVMLifecycleMethodsWithoutAServerAnswerAreUnmapped(t *testing.T) {
	conn := (&Adapter{}).Connection()
	for _, method := range []string{
		platformv1.ComputeService_StartVM_FullMethodName,
		platformv1.ComputeService_StopVM_FullMethodName,
		platformv1.ComputeService_DeleteVM_FullMethodName,
	} {
		t.Run(method, func(t *testing.T) {
			err := conn.Invoke(context.Background(), method, &platformv1.StartVMRequest{Id: "vm-1"}, nil)
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("Invoke() = %v, want Unimplemented", err)
			}
		})
	}
}

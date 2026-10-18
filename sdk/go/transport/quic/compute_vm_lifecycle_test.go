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

//go:build codec_msgpack

package quic

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// vmSubOpcodes are the VM verbs platformd answers over QUIC, each a
// sub-opcode under OpVMExtendedCategory
// (pkg/api/daemon/quic_vm_pb.go::handleVMPB).
var vmSubOpcodes = map[string]byte{
	platformv1.ComputeService_CreateVM_FullMethodName:  quicwire.OpVMCreate,
	platformv1.ComputeService_GetVM_FullMethodName:     quicwire.OpVMGet,
	platformv1.ComputeService_ListVMs_FullMethodName:   quicwire.OpVMList,
	platformv1.ComputeService_StartVM_FullMethodName:   quicwire.OpVMStart,
	platformv1.ComputeService_StopVM_FullMethodName:    quicwire.OpVMStop,
	platformv1.ComputeService_DeleteVM_FullMethodName:  quicwire.OpVMDelete,
	platformv1.ComputeService_RebootVM_FullMethodName:  quicwire.OpVMRestart,
	platformv1.ComputeService_SuspendVM_FullMethodName: quicwire.OpVMSuspend,
	platformv1.ComputeService_ResumeVM_FullMethodName:  quicwire.OpVMResume,

	platformv1.ComputeService_CreateSnapshot_FullMethodName:      quicwire.OpVMSnapshotCreate,
	platformv1.ComputeService_RestoreSnapshot_FullMethodName:     quicwire.OpVMSnapshotRestore,
	platformv1.ComputeService_DeleteSnapshot_FullMethodName:      quicwire.OpVMSnapshotDelete,
	platformv1.ComputeService_ListSnapshots_FullMethodName:       quicwire.OpVMSnapshotList,
	platformv1.ComputeService_AttestVM_FullMethodName:            quicwire.OpVMAttest,
	platformv1.ComputeService_VerifyVMAttestation_FullMethodName: quicwire.OpVMVerifyAttest,
}

// TestVMMethodsRouteToTheVMCategory pins the wire contract: a wrong
// sub-opcode makes the daemon run the wrong verb on the VM.
func TestVMMethodsRouteToTheVMCategory(t *testing.T) {
	for method, wantSub := range vmSubOpcodes {
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

// TestVMCRUDMethodsSendThePBRequest checks each CRUD verb puts its pb
// request on the wire after the sub-opcode, which the daemon decodes into
// the same pb message.
func TestVMCRUDMethodsSendThePBRequest(t *testing.T) {
	tests := []struct {
		method string
		args   interface{}
		decode func(t *testing.T, body []byte) string
		want   string
	}{
		{
			method: platformv1.ComputeService_CreateVM_FullMethodName,
			args:   &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "web-1"}},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.CreateVMRequest
				decodeVMBody(t, body, &req)
				return req.GetConfig().GetName()
			},
			want: "web-1",
		},
		{
			method: platformv1.ComputeService_GetVM_FullMethodName,
			args:   &platformv1.GetVMRequest{Id: "vm-1"},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.GetVMRequest
				decodeVMBody(t, body, &req)
				return req.GetId()
			},
			want: "vm-1",
		},
		{
			method: platformv1.ComputeService_ListVMs_FullMethodName,
			args:   &platformv1.ListVMsRequest{States: []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING}},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.ListVMsRequest
				decodeVMBody(t, body, &req)
				if len(req.GetStates()) != 1 {
					return ""
				}
				return req.GetStates()[0].String()
			},
			want: platformv1.VMState_VM_STATE_RUNNING.String(),
		},
		{
			method: platformv1.ComputeService_StartVM_FullMethodName,
			args:   &platformv1.StartVMRequest{Id: "vm-2"},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.StartVMRequest
				decodeVMBody(t, body, &req)
				return req.GetId()
			},
			want: "vm-2",
		},
		{
			method: platformv1.ComputeService_StopVM_FullMethodName,
			args:   &platformv1.StopVMRequest{Id: "vm-3", Force: true},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.StopVMRequest
				decodeVMBody(t, body, &req)
				if !req.GetForce() {
					return ""
				}
				return req.GetId()
			},
			want: "vm-3",
		},
		{
			method: platformv1.ComputeService_DeleteVM_FullMethodName,
			args:   &platformv1.DeleteVMRequest{Id: "vm-4", DeleteDisks: true},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.DeleteVMRequest
				decodeVMBody(t, body, &req)
				if !req.GetDeleteDisks() {
					return ""
				}
				return req.GetId()
			},
			want: "vm-4",
		},
		{
			method: platformv1.ComputeService_CreateSnapshot_FullMethodName,
			args:   &platformv1.CreateSnapshotRequest{VmId: "vm-5", Config: &platformv1.SnapshotConfig{Name: "nightly"}},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.CreateSnapshotRequest
				decodeVMBody(t, body, &req)
				return req.GetVmId() + "/" + req.GetConfig().GetName()
			},
			want: "vm-5/nightly",
		},
		{
			method: platformv1.ComputeService_RestoreSnapshot_FullMethodName,
			args:   &platformv1.RestoreSnapshotRequest{VmId: "vm-5", SnapshotId: "snap-1"},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.RestoreSnapshotRequest
				decodeVMBody(t, body, &req)
				return req.GetVmId() + "/" + req.GetSnapshotId()
			},
			want: "vm-5/snap-1",
		},
		{
			method: platformv1.ComputeService_DeleteSnapshot_FullMethodName,
			args:   &platformv1.DeleteSnapshotRequest{VmId: "vm-5", SnapshotId: "snap-2"},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.DeleteSnapshotRequest
				decodeVMBody(t, body, &req)
				return req.GetVmId() + "/" + req.GetSnapshotId()
			},
			want: "vm-5/snap-2",
		},
		{
			method: platformv1.ComputeService_ListSnapshots_FullMethodName,
			args:   &platformv1.ListSnapshotsRequest{VmId: "vm-6"},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.ListSnapshotsRequest
				decodeVMBody(t, body, &req)
				return req.GetVmId()
			},
			want: "vm-6",
		},
		{
			method: platformv1.ComputeService_AttestVM_FullMethodName,
			args:   &platformv1.AttestVMRequest{VmId: "vm-7", Nonce: []byte("n1"), PcrIndices: []uint32{0, 7}},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.AttestVMRequest
				decodeVMBody(t, body, &req)
				return fmt.Sprintf("%s/%s/%v", req.GetVmId(), req.GetNonce(), req.GetPcrIndices())
			},
			want: "vm-7/n1/[0 7]",
		},
		{
			method: platformv1.ComputeService_VerifyVMAttestation_FullMethodName,
			args:   &platformv1.VerifyVMAttestationRequest{VmId: "vm-8", Quote: []byte("q"), SignatureAlgorithm: "SHA256-RSAPSS"},
			decode: func(t *testing.T, body []byte) string {
				var req platformv1.VerifyVMAttestationRequest
				decodeVMBody(t, body, &req)
				return req.GetVmId() + "/" + string(req.GetQuote()) + "/" + req.GetSignatureAlgorithm()
			},
			want: "vm-8/q/SHA256-RSAPSS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			if err := conn.Invoke(context.Background(), tt.method, tt.args, nil); err != nil {
				t.Fatalf("Invoke() error = %v", err)
			}
			if sender.rawOpcode != quicwire.OpVMExtendedCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", sender.rawOpcode, quicwire.OpVMExtendedCategory)
			}
			if len(sender.rawPayload) == 0 || sender.rawPayload[0] != vmSubOpcodes[tt.method] {
				t.Fatalf("payload = %x, want sub-opcode 0x%02x first", sender.rawPayload, vmSubOpcodes[tt.method])
			}
			if got := tt.decode(t, sender.rawPayload[1:]); got != tt.want {
				t.Fatalf("decoded request = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestVMReadMethodsDecodeTheReply checks GetVM and ListVMs hand the
// caller the VMs the daemon answered.
func TestVMReadMethodsDecodeTheReply(t *testing.T) {
	t.Run("GetVM", func(t *testing.T) {
		sender := &recordingSender{respPayload: encodeVMBody(t, &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: "vm-1"}})}
		conn := newConnWithSender(t, sender)

		var reply platformv1.GetVMResponse
		if err := conn.Invoke(context.Background(), platformv1.ComputeService_GetVM_FullMethodName, &platformv1.GetVMRequest{Id: "vm-1"}, &reply); err != nil {
			t.Fatalf("Invoke() error = %v", err)
		}
		if reply.GetVm().GetId() != "vm-1" {
			t.Fatalf("reply VM = %q, want vm-1", reply.GetVm().GetId())
		}
	})

	t.Run("ListVMs", func(t *testing.T) {
		answer := &platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1"}, {Id: "vm-2"}}}
		sender := &recordingSender{respPayload: encodeVMBody(t, answer)}
		conn := newConnWithSender(t, sender)

		var reply platformv1.ListVMsResponse
		if err := conn.Invoke(context.Background(), platformv1.ComputeService_ListVMs_FullMethodName, &platformv1.ListVMsRequest{}, &reply); err != nil {
			t.Fatalf("Invoke() error = %v", err)
		}
		if len(reply.GetVms()) != 2 || reply.GetVms()[1].GetId() != "vm-2" {
			t.Fatalf("reply VMs = %v, want vm-1 and vm-2", reply.GetVms())
		}
	})

	t.Run("CreateSnapshot", func(t *testing.T) {
		answer := &platformv1.CreateSnapshotResponse{Snapshot: &platformv1.Snapshot{Id: "snap-1", VmId: "vm-1"}}
		sender := &recordingSender{respPayload: encodeVMBody(t, answer)}
		conn := newConnWithSender(t, sender)

		var reply platformv1.CreateSnapshotResponse
		args := &platformv1.CreateSnapshotRequest{VmId: "vm-1", Config: &platformv1.SnapshotConfig{Name: "nightly"}}
		if err := conn.Invoke(context.Background(), platformv1.ComputeService_CreateSnapshot_FullMethodName, args, &reply); err != nil {
			t.Fatalf("Invoke() error = %v", err)
		}
		if reply.GetSnapshot().GetId() != "snap-1" {
			t.Fatalf("reply snapshot = %q, want snap-1", reply.GetSnapshot().GetId())
		}
	})

	t.Run("ListSnapshots", func(t *testing.T) {
		answer := &platformv1.ListSnapshotsResponse{Snapshots: []*platformv1.Snapshot{{Id: "snap-1"}, {Id: "snap-2"}}}
		sender := &recordingSender{respPayload: encodeVMBody(t, answer)}
		conn := newConnWithSender(t, sender)

		var reply platformv1.ListSnapshotsResponse
		if err := conn.Invoke(context.Background(), platformv1.ComputeService_ListSnapshots_FullMethodName, &platformv1.ListSnapshotsRequest{VmId: "vm-1"}, &reply); err != nil {
			t.Fatalf("Invoke() error = %v", err)
		}
		if len(reply.GetSnapshots()) != 2 || reply.GetSnapshots()[1].GetId() != "snap-2" {
			t.Fatalf("reply snapshots = %v, want snap-1 and snap-2", reply.GetSnapshots())
		}
	})

	t.Run("AttestVM", func(t *testing.T) {
		answer := &platformv1.AttestVMResponse{Quote: []byte("quote"), SignatureAlgorithm: "SHA256-RSAPSS"}
		sender := &recordingSender{respPayload: encodeVMBody(t, answer)}
		conn := newConnWithSender(t, sender)

		var reply platformv1.AttestVMResponse
		if err := conn.Invoke(context.Background(), platformv1.ComputeService_AttestVM_FullMethodName, &platformv1.AttestVMRequest{VmId: "vm-1"}, &reply); err != nil {
			t.Fatalf("Invoke() error = %v", err)
		}
		if string(reply.GetQuote()) != "quote" || reply.GetSignatureAlgorithm() != "SHA256-RSAPSS" {
			t.Fatalf("reply = %q/%q, want quote/SHA256-RSAPSS", reply.GetQuote(), reply.GetSignatureAlgorithm())
		}
	})

	t.Run("VerifyVMAttestation", func(t *testing.T) {
		answer := &platformv1.VerifyVMAttestationResponse{Verified: true, Message: "attestation verified"}
		sender := &recordingSender{respPayload: encodeVMBody(t, answer)}
		conn := newConnWithSender(t, sender)

		var reply platformv1.VerifyVMAttestationResponse
		if err := conn.Invoke(context.Background(), platformv1.ComputeService_VerifyVMAttestation_FullMethodName, &platformv1.VerifyVMAttestationRequest{VmId: "vm-1"}, &reply); err != nil {
			t.Fatalf("Invoke() error = %v", err)
		}
		if !reply.GetVerified() || reply.GetMessage() != "attestation verified" {
			t.Fatalf("reply = %v/%q, want verified", reply.GetVerified(), reply.GetMessage())
		}
	})
}

// TestVMCRUDMethodsKeepTheDaemonErrorClass checks a daemon refusal reaches
// the caller with the gRPC code that matches its QUIC status.
func TestVMCRUDMethodsKeepTheDaemonErrorClass(t *testing.T) {
	tests := []struct {
		method string
		args   interface{}
		status byte
		want   codes.Code
	}{
		{platformv1.ComputeService_CreateVM_FullMethodName, &platformv1.CreateVMRequest{}, quicwire.StatusInvalidArgument, codes.InvalidArgument},
		{platformv1.ComputeService_GetVM_FullMethodName, &platformv1.GetVMRequest{Id: "gone"}, quicwire.StatusNotFound, codes.NotFound},
		{platformv1.ComputeService_ListVMs_FullMethodName, &platformv1.ListVMsRequest{}, quicwire.StatusUnavailable, codes.Unavailable},
		{platformv1.ComputeService_StartVM_FullMethodName, &platformv1.StartVMRequest{Id: "vm-1"}, quicwire.StatusFailedPrecondition, codes.FailedPrecondition},
		{platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1"}, quicwire.StatusFailedPrecondition, codes.FailedPrecondition},
		{platformv1.ComputeService_DeleteVM_FullMethodName, &platformv1.DeleteVMRequest{Id: "gone"}, quicwire.StatusNotFound, codes.NotFound},
		{platformv1.ComputeService_CreateSnapshot_FullMethodName, &platformv1.CreateSnapshotRequest{}, quicwire.StatusInvalidArgument, codes.InvalidArgument},
		{platformv1.ComputeService_RestoreSnapshot_FullMethodName, &platformv1.RestoreSnapshotRequest{VmId: "vm-1", SnapshotId: "gone"}, quicwire.StatusNotFound, codes.NotFound},
		{platformv1.ComputeService_DeleteSnapshot_FullMethodName, &platformv1.DeleteSnapshotRequest{VmId: "vm-1", SnapshotId: "gone"}, quicwire.StatusNotFound, codes.NotFound},
		{platformv1.ComputeService_ListSnapshots_FullMethodName, &platformv1.ListSnapshotsRequest{VmId: "vm-1"}, quicwire.StatusFailedPrecondition, codes.FailedPrecondition},
		{platformv1.ComputeService_AttestVM_FullMethodName, &platformv1.AttestVMRequest{}, quicwire.StatusInvalidArgument, codes.InvalidArgument},
		{platformv1.ComputeService_VerifyVMAttestation_FullMethodName, &platformv1.VerifyVMAttestationRequest{VmId: "gone"}, quicwire.StatusNotFound, codes.NotFound},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{sendRequestErr: &quicwire.ErrProtocol{Status: tt.status, Message: "refused"}}
			conn := newConnWithSender(t, sender)

			err := conn.Invoke(context.Background(), tt.method, tt.args, nil)
			if status.Code(err) != tt.want {
				t.Fatalf("Invoke() = %v, want %s", err, tt.want)
			}
		})
	}
}

// encodeVMBody encodes a pb message in the QUIC payload codec.
func encodeVMBody(t *testing.T, msg interface{}) []byte {
	t.Helper()
	body, err := quicwire.EncodePayload(msg)
	if err != nil {
		t.Fatalf("EncodePayload() error = %v", err)
	}
	return body
}

// decodeVMBody decodes a QUIC payload body into a pb message.
func decodeVMBody(t *testing.T, body []byte, msg interface{}) {
	t.Helper()
	if err := quicwire.DecodePayload(body, msg); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
}

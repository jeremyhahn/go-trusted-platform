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

package mcp

import (
	"encoding/json"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmStatus is the status every vm_* lifecycle tool without a VM answers.
func vmStatus() *platformv1.Status {
	return &platformv1.Status{Success: true, Message: "done"}
}

// vmStatusResult is vmStatus as the protojson reply a vm_* tool returns.
func vmStatusResult() map[string]interface{} {
	return map[string]interface{}{"status": map[string]interface{}{"success": true, "message": "done"}}
}

// vmLifecycleCalls are the nine VM lifecycle methods, each with a request
// that sets every field its tool must carry and the reply its tool answers.
var vmLifecycleCalls = []struct {
	method string
	tool   string
	req    proto.Message
	reply  proto.Message
}{
	{
		platformv1.ComputeService_CreateVM_FullMethodName, "vm_create",
		&platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{
				Name:       "vm-1",
				Firmware:   platformv1.FirmwareType_FIRMWARE_TYPE_UEFI,
				Cpu:        &platformv1.CPUConfig{Cores: 2},
				Memory:     &platformv1.MemoryConfig{SizeMb: 2048},
				Disks:      []*platformv1.DiskConfig{{Id: "root", SizeGb: 20, Bootable: true}},
				Tpm:        &platformv1.TPMConfig{Enabled: true},
				SecureBoot: true,
				Labels:     map[string]string{"tier": "web"},
			},
			Start: true,
		},
		&platformv1.CreateVMResponse{
			Status: vmStatus(),
			Vm:     &platformv1.VM{Id: "vm-1", State: platformv1.VMState_VM_STATE_RUNNING},
		},
	},
	{
		platformv1.ComputeService_ListVMs_FullMethodName, "vm_list",
		&platformv1.ListVMsRequest{
			Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
			Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10},
			States:     []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING, platformv1.VMState_VM_STATE_PAUSED},
		},
		&platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1", State: platformv1.VMState_VM_STATE_PAUSED}}},
	},
	{
		platformv1.ComputeService_GetVM_FullMethodName, "vm_get",
		&platformv1.GetVMRequest{Id: "vm-1"},
		&platformv1.GetVMResponse{Vm: &platformv1.VM{Id: "vm-1", State: platformv1.VMState_VM_STATE_STOPPED}},
	},
	{
		platformv1.ComputeService_DeleteVM_FullMethodName, "vm_delete",
		&platformv1.DeleteVMRequest{Id: "vm-1", DeleteDisks: true},
		&platformv1.DeleteVMResponse{Status: vmStatus()},
	},
	{
		platformv1.ComputeService_StartVM_FullMethodName, "vm_start",
		&platformv1.StartVMRequest{Id: "vm-1"},
		&platformv1.StartVMResponse{Status: vmStatus()},
	},
	{
		platformv1.ComputeService_StopVM_FullMethodName, "vm_stop",
		&platformv1.StopVMRequest{Id: "vm-1", Force: true, TimeoutSeconds: 30},
		&platformv1.StopVMResponse{Status: vmStatus()},
	},
	{
		platformv1.ComputeService_RebootVM_FullMethodName, "vm_reboot",
		&platformv1.RebootVMRequest{Id: "vm-1", Force: true},
		&platformv1.RebootVMResponse{Status: vmStatus()},
	},
	{
		platformv1.ComputeService_SuspendVM_FullMethodName, "vm_suspend",
		&platformv1.SuspendVMRequest{Id: "vm-1"},
		&platformv1.SuspendVMResponse{Status: vmStatus()},
	},
	{
		platformv1.ComputeService_ResumeVM_FullMethodName, "vm_resume",
		&platformv1.ResumeVMRequest{Id: "vm-1"},
		&platformv1.ResumeVMResponse{Status: vmStatus()},
	},
}

// protoNamesMap is a message in the protojson form the vm_* tools take and
// answer.
func protoNamesMap(t *testing.T, message proto.Message) map[string]interface{} {
	t.Helper()
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		t.Fatalf("marshal %T: %v", message, err)
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %T: %v", message, err)
	}
	return out
}

// Each VM lifecycle method calls its tool with the full request, so no
// field is dropped on the way, and decodes the tool's answer as the reply.
func TestVMLifecycleMethodsCarryTheFullRequest(t *testing.T) {
	for _, tt := range vmLifecycleCalls {
		t.Run(tt.tool, func(t *testing.T) {
			reply := tt.reply.ProtoReflect().New().Interface()
			results := map[string]interface{}{tt.tool: protoNamesMap(t, tt.reply)}
			calls, err := invokePhase35(t, results, tt.method, tt.req, reply)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if len(calls) != 1 || calls[0].Name != tt.tool {
				t.Fatalf("calls = %+v, want one %s call", calls, tt.tool)
			}

			data, err := json.Marshal(calls[0].Arguments)
			if err != nil {
				t.Fatalf("marshal arguments: %v", err)
			}
			got := tt.req.ProtoReflect().New().Interface()
			if err := protojson.Unmarshal(data, got); err != nil {
				t.Fatalf("arguments %s are not the request: %v", data, err)
			}
			if !proto.Equal(got, tt.req) {
				t.Errorf("tool request = %v, want %v", got, tt.req)
			}
			if !proto.Equal(reply, tt.reply) {
				t.Errorf("reply = %v, want %v", reply, tt.reply)
			}
		})
	}
}

// A request that is not a proto message is refused before any tool runs.
func TestVMLifecycleMethodsRejectANonProtoRequest(t *testing.T) {
	for _, tt := range vmLifecycleCalls {
		t.Run(tt.tool, func(t *testing.T) {
			build, ok := mcpArgBuilders[tt.method]
			if !ok {
				t.Fatalf("no argument builder for %s", tt.method)
			}
			if _, err := build("vm-1"); err != (ErrUnexpectedArgsType{Method: tt.method}) {
				t.Fatalf("err = %v, want ErrUnexpectedArgsType", err)
			}
		})
	}
}

func TestVMFieldArgsRejectsANonProtoRequest(t *testing.T) {
	const method = platformv1.ComputeService_ListSnapshots_FullMethodName
	if _, err := vmFieldArgs("vm_id")(method)("vm-1"); err != (ErrUnexpectedArgsType{Method: method}) {
		t.Fatalf("err = %v, want ErrUnexpectedArgsType", err)
	}
}

// Each snapshot and attestation method calls its vm_* tool with the
// arguments that tool takes and decodes the RPC's protojson reply.
func TestVMSnapshotAttestMethodsCallTheirTool(t *testing.T) {
	tests := []struct {
		method string
		tool   string
		req    proto.Message
		result map[string]interface{}
		reply  proto.Message
		args   map[string]interface{}
		want   proto.Message
	}{
		{platformv1.ComputeService_CreateSnapshot_FullMethodName, "vm_snapshot_create",
			&platformv1.CreateSnapshotRequest{VmId: "vm-1", Config: &platformv1.SnapshotConfig{
				Name: "nightly", Description: "before upgrade", MemorySnapshot: true, DiskSnapshot: true}},
			map[string]interface{}{"snapshot": map[string]interface{}{"id": "snap-1", "vm_id": "vm-1"}},
			&platformv1.CreateSnapshotResponse{},
			map[string]interface{}{"vm_id": "vm-1", "name": "nightly", "description": "before upgrade",
				"memory_snapshot": true, "disk_snapshot": true},
			&platformv1.CreateSnapshotResponse{Snapshot: &platformv1.Snapshot{Id: "snap-1", VmId: "vm-1"}}},
		{platformv1.ComputeService_ListSnapshots_FullMethodName, "vm_snapshot_list",
			&platformv1.ListSnapshotsRequest{VmId: "vm-1"},
			map[string]interface{}{"snapshots": []interface{}{map[string]interface{}{"id": "snap-1"}}},
			&platformv1.ListSnapshotsResponse{},
			map[string]interface{}{"vm_id": "vm-1"},
			&platformv1.ListSnapshotsResponse{Snapshots: []*platformv1.Snapshot{{Id: "snap-1"}}}},
		{platformv1.ComputeService_DeleteSnapshot_FullMethodName, "vm_snapshot_delete",
			&platformv1.DeleteSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
			vmStatusResult(), &platformv1.DeleteSnapshotResponse{},
			map[string]interface{}{"vm_id": "vm-1", "snapshot_id": "snap-1"},
			&platformv1.DeleteSnapshotResponse{Status: &platformv1.Status{Success: true, Message: "done"}}},
		{platformv1.ComputeService_RestoreSnapshot_FullMethodName, "vm_snapshot_restore",
			&platformv1.RestoreSnapshotRequest{VmId: "vm-1", SnapshotId: "snap-1"},
			vmStatusResult(), &platformv1.RestoreSnapshotResponse{},
			map[string]interface{}{"vm_id": "vm-1", "snapshot_id": "snap-1"},
			&platformv1.RestoreSnapshotResponse{Status: &platformv1.Status{Success: true, Message: "done"}}},
		{platformv1.ComputeService_AttestVM_FullMethodName, "vm_attest",
			&platformv1.AttestVMRequest{VmId: "vm-1", Nonce: []byte("nonce"), PcrIndices: []uint32{0, 7},
				PcrBank: platformv1.PCRBank_PCR_BANK_SHA256},
			map[string]interface{}{"quote": "cQ==", "signature": "cw==", "signature_algorithm": "SHA256-RSAPSS"},
			&platformv1.AttestVMResponse{},
			map[string]interface{}{"vm_id": "vm-1", "nonce": "bm9uY2U=",
				"include_pcrs": []interface{}{float64(0), float64(7)}},
			&platformv1.AttestVMResponse{Quote: []byte("q"), Signature: []byte("s"), SignatureAlgorithm: "SHA256-RSAPSS"}},
		{platformv1.ComputeService_VerifyVMAttestation_FullMethodName, "vm_attest_verify",
			&platformv1.VerifyVMAttestationRequest{VmId: "vm-1", Quote: []byte("q"), Signature: []byte("s"),
				SignatureAlgorithm: "SHA256-RSAPSS", Nonce: []byte("nonce"),
				ExpectedPcrs: []*platformv1.PCRValue{{Index: 7, Value: []byte("v7")}}},
			map[string]interface{}{"verified": true, "message": "ok"},
			&platformv1.VerifyVMAttestationResponse{},
			map[string]interface{}{"vm_id": "vm-1", "quote": "cQ==", "signature": "cw==",
				"signature_algorithm": "SHA256-RSAPSS", "nonce": "bm9uY2U=",
				"expected_pcrs": map[string]interface{}{"7": "djc="}},
			&platformv1.VerifyVMAttestationResponse{Verified: true, Message: "ok"}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			calls, err := invokePhase35(t, map[string]interface{}{tt.tool: tt.result}, tt.method, tt.req, tt.reply)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if len(calls) != 1 || calls[0].Name != tt.tool {
				t.Fatalf("calls = %+v, want one %s call", calls, tt.tool)
			}
			if !reflect.DeepEqual(calls[0].Arguments, tt.args) {
				t.Errorf("arguments = %v, want %v", calls[0].Arguments, tt.args)
			}
			if !proto.Equal(tt.reply, tt.want) {
				t.Errorf("reply = %v, want %v", tt.reply, tt.want)
			}
		})
	}
}

// The vm_attest tools quote and compare the SHA-256 bank only, so a request
// naming another bank is refused before the call.
func TestVMAttestMethodsRefuseAnotherPCRBank(t *testing.T) {
	tests := []struct {
		name   string
		method string
		req    proto.Message
		field  string
	}{
		{"attest SHA-1 bank", platformv1.ComputeService_AttestVM_FullMethodName,
			&platformv1.AttestVMRequest{VmId: "vm-1", PcrBank: platformv1.PCRBank_PCR_BANK_SHA1}, "pcr_bank"},
		{"verify SHA-384 value", platformv1.ComputeService_VerifyVMAttestation_FullMethodName,
			&platformv1.VerifyVMAttestationRequest{VmId: "vm-1", ExpectedPcrs: []*platformv1.PCRValue{
				{Index: 7, Bank: platformv1.PCRBank_PCR_BANK_SHA384, Value: []byte("v")}}}, "expected_pcrs.bank"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls, err := invokePhase35(t, map[string]interface{}{}, tt.method, tt.req, nil)
			requireCode(t, err, codes.InvalidArgument)
			want := ErrFieldNotSupported{Method: tt.method, Field: tt.field}.Error()
			if status.Convert(err).Message() != want {
				t.Errorf("message = %q, want %q", status.Convert(err).Message(), want)
			}
			if len(calls) != 0 {
				t.Errorf("a refused request reached the tool: %+v", calls)
			}
		})
	}
}

func TestVMSnapshotAttestArgsRejectAnotherRequestType(t *testing.T) {
	for method, entry := range vmSnapshotAttestTools {
		if _, err := entry.build(method)(&platformv1.StartVMRequest{Id: "vm-1"}); err == nil {
			t.Errorf("%s accepted a StartVMRequest", method)
		}
	}
	for _, method := range []string{
		platformv1.ComputeService_CreateSnapshot_FullMethodName,
		platformv1.ComputeService_AttestVM_FullMethodName,
		platformv1.ComputeService_VerifyVMAttestation_FullMethodName,
	} {
		if _, err := vmSnapshotAttestTools[method].build(method)("vm-1"); err != (ErrUnexpectedArgsType{Method: method}) {
			t.Errorf("%s: err = %v, want ErrUnexpectedArgsType", method, err)
		}
	}
}

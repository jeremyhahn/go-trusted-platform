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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmStatusResult is the protojson reply every vm_* lifecycle tool returns.
func vmStatusResult() map[string]interface{} {
	return map[string]interface{}{"status": map[string]interface{}{"success": true, "message": "done"}}
}

func TestVMLifecycleMethodsCallTheirToolWithTheID(t *testing.T) {
	tests := []struct {
		method string
		tool   string
		req    proto.Message
		reply  interface{ GetStatus() *platformv1.Status }
	}{
		{platformv1.ComputeService_StartVM_FullMethodName, "vm_start", &platformv1.StartVMRequest{Id: "vm-1"}, &platformv1.StartVMResponse{}},
		{platformv1.ComputeService_StopVM_FullMethodName, "vm_stop", &platformv1.StopVMRequest{Id: "vm-1"}, &platformv1.StopVMResponse{}},
		{platformv1.ComputeService_RebootVM_FullMethodName, "vm_reboot", &platformv1.RebootVMRequest{Id: "vm-1"}, &platformv1.RebootVMResponse{}},
		{platformv1.ComputeService_SuspendVM_FullMethodName, "vm_suspend", &platformv1.SuspendVMRequest{Id: "vm-1"}, &platformv1.SuspendVMResponse{}},
		{platformv1.ComputeService_ResumeVM_FullMethodName, "vm_resume", &platformv1.ResumeVMRequest{Id: "vm-1"}, &platformv1.ResumeVMResponse{}},
		{platformv1.ComputeService_DeleteVM_FullMethodName, "vm_delete", &platformv1.DeleteVMRequest{Id: "vm-1"}, &platformv1.DeleteVMResponse{}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			calls, err := invokePhase35(t, map[string]interface{}{tt.tool: vmStatusResult()}, tt.method, tt.req, tt.reply)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if len(calls) != 1 || calls[0].Name != tt.tool {
				t.Fatalf("calls = %+v, want one %s call", calls, tt.tool)
			}
			if len(calls[0].Arguments) != 1 || calls[0].Arguments["id"] != "vm-1" {
				t.Errorf("arguments = %v, want only id vm-1", calls[0].Arguments)
			}
			if got := tt.reply.GetStatus(); !got.GetSuccess() || got.GetMessage() != "done" {
				t.Errorf("reply status = %v, want success with message done", got)
			}
		})
	}
}

// The vm_* tools take only an id; a field they cannot carry is refused
// before the call instead of being dropped.
func TestVMLifecycleMethodsRefuseFieldsTheToolCannotCarry(t *testing.T) {
	tests := []struct {
		name   string
		method string
		req    proto.Message
		field  string
	}{
		{"stop force", platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1", Force: true}, "force"},
		{"stop timeout", platformv1.ComputeService_StopVM_FullMethodName, &platformv1.StopVMRequest{Id: "vm-1", TimeoutSeconds: 30}, "timeout_seconds"},
		{"reboot force", platformv1.ComputeService_RebootVM_FullMethodName, &platformv1.RebootVMRequest{Id: "vm-1", Force: true}, "force"},
		{"delete disks", platformv1.ComputeService_DeleteVM_FullMethodName, &platformv1.DeleteVMRequest{Id: "vm-1", DeleteDisks: true}, "delete_disks"},
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

func TestVMByIDArgsRejectsANonProtoRequest(t *testing.T) {
	const method = platformv1.ComputeService_StartVM_FullMethodName
	if _, err := vmByIDArgs(method)("vm-1"); err != (ErrUnexpectedArgsType{Method: method}) {
		t.Fatalf("err = %v, want ErrUnexpectedArgsType", err)
	}
}

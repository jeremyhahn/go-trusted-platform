// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

// MCP-vs-gRPC parity for the nine VM lifecycle tools (#304, #317, #704): each MCP
// call must answer exactly what its ComputeService RPC answers, reply and
// error class alike.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// vmLifecycleCall is one lifecycle operation made through MCP and through
// gRPC against the same orchestrator state. args are the tool arguments.
type vmLifecycleCall struct {
	name string
	args func(id string) map[string]interface{}
	grpc func(*ComputeGRPCService, string) (proto.Message, error)
}

// vmByID is the arguments of a tool whose request is the VM id alone.
func vmByID(id string) map[string]interface{} {
	return map[string]interface{}{"id": id}
}

// vmLifecycleCalls are the nine tools and their RPCs. vm_create takes the
// id as the VM name; vm_list ignores it.
var vmLifecycleCalls = []vmLifecycleCall{
	{
		"vm_create",
		func(id string) map[string]interface{} {
			return map[string]interface{}{"config": map[string]interface{}{"name": id}}
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: id}})
		},
	},
	{
		"vm_list",
		func(string) map[string]interface{} { return map[string]interface{}{} },
		func(s *ComputeGRPCService, _ string) (proto.Message, error) {
			return s.ListVMs(context.Background(), &platformv1.ListVMsRequest{})
		},
	},
	{
		"vm_get",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.GetVM(context.Background(), &platformv1.GetVMRequest{Id: id})
		},
	},
	{
		"vm_delete",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.DeleteVM(context.Background(), &platformv1.DeleteVMRequest{Id: id})
		},
	},
	{
		"vm_start",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.StartVM(context.Background(), &platformv1.StartVMRequest{Id: id})
		},
	},
	{
		"vm_stop",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.StopVM(context.Background(), &platformv1.StopVMRequest{Id: id})
		},
	},
	{
		"vm_reboot",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: id})
		},
	},
	{
		"vm_suspend",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.SuspendVM(context.Background(), &platformv1.SuspendVMRequest{Id: id})
		},
	},
	{
		"vm_resume",
		vmByID,
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.ResumeVM(context.Background(), &platformv1.ResumeVMRequest{Id: id})
		},
	},
}

// mcp runs the call's tool through the MCP tool registry the daemon builds
// over provider.
func (c vmLifecycleCall) mcp(provider *MCPServiceProvider, id string) (interface{}, error) {
	return runVMTool(provider, c.name, c.args(id))
}

// runVMTool runs one tool through the MCP tool registry over provider.
func runVMTool(provider *MCPServiceProvider, tool string, args map[string]interface{}) (interface{}, error) {
	return mcp.NewToolRegistry(provider, logging.DefaultLogger()).ExecuteTool(context.Background(), tool, args)
}

// seededVMPair is a parity pair whose orchestrator holds vm-1 and creates
// VMs with fixed timestamps, so two pairs answer byte-identical replies.
func seededVMPair() (*MCPServiceProvider, *ComputeGRPCService, *computeParityOrchestrator) {
	provider, svc, orch := newComputeParityPair()
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	orch.instances["vm-1"] = &compute.Instance{
		ID: "vm-1", Name: "vm-1", Type: compute.ComputeTypeVM, State: compute.StateStopped,
		CreatedAt: at, UpdatedAt: at,
	}
	orch.createFunc = func(_ context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
		return &compute.Instance{
			ID: profile.Name + "-instance", Name: profile.Name, Type: compute.ComputeTypeVM,
			State: compute.StateStopped, CreatedAt: at, UpdatedAt: at,
		}, nil
	}
	return provider, svc, orch
}

func TestVMLifecycleParity_Replies(t *testing.T) {
	for _, call := range vmLifecycleCalls {
		t.Run(call.name, func(t *testing.T) {
			// Separate pairs: start, stop and delete change the state the
			// other side would then read.
			provider, _, _ := seededVMPair()
			_, svc, _ := seededVMPair()

			mcpResult, err := call.mcp(provider, "vm-1")
			require.NoError(t, err)
			grpcResp, err := call.grpc(svc, "vm-1")
			require.NoError(t, err)

			want, err := protoResultJSON.Marshal(grpcResp)
			require.NoError(t, err)
			got, err := json.Marshal(mcpResult)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func TestVMLifecycleParity_CreateBuildsTheSameSpec(t *testing.T) {
	memory, cpus := uint64(4096), uint32(2)
	args := map[string]interface{}{"config": map[string]interface{}{
		"name":        "vm-9",
		"memory":      map[string]interface{}{"size_mb": memory},
		"cpu":         map[string]interface{}{"cores": cpus},
		"tpm":         map[string]interface{}{"enabled": true, "version": "TPM_VERSION_2_0"},
		"secure_boot": true,
	}}
	req := &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:       "vm-9",
		Memory:     &platformv1.MemoryConfig{SizeMb: memory},
		Cpu:        &platformv1.CPUConfig{Cores: cpus},
		Tpm:        &platformv1.TPMConfig{Enabled: true, Version: platformv1.TPMVersion_TPM_VERSION_2_0},
		SecureBoot: true,
	}}

	provider, svc, orch := seededVMPair()

	_, err := runVMTool(provider, "vm_create", args)
	require.NoError(t, err)
	_, err = svc.CreateVM(context.Background(), req)
	require.NoError(t, err)

	specs := orch.recordedSpecs()
	require.Len(t, specs, 2)
	assert.Equal(t, compute.VMSpec{MemoryMB: 4096, CPUs: 2, SecureBoot: true}, specs[1])
	assert.Equal(t, specs[1], specs[0], "MCP must hand the orchestrator what gRPC does")
}

func TestVMLifecycleParity_CreateRefusesTheSameField(t *testing.T) {
	args := map[string]interface{}{"config": map[string]interface{}{
		"name":     "vm-9",
		"firmware": "FIRMWARE_TYPE_BIOS",
	}}
	req := &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:     "vm-9",
		Firmware: platformv1.FirmwareType_FIRMWARE_TYPE_BIOS,
	}}

	provider, svc, orch := seededVMPair()

	_, mcpErr := runVMTool(provider, "vm_create", args)
	_, grpcErr := svc.CreateVM(context.Background(), req)

	require.Error(t, grpcErr)
	require.Error(t, mcpErr)
	assert.Equal(t, codes.InvalidArgument, status.Code(grpcErr))
	assert.Contains(t, grpcErr.Error(), "config.firmware")
	assert.Contains(t, mcpErr.Error(), grpcErr.Error(), "MCP must refuse what gRPC does")
	assert.Empty(t, orch.recordedSpecs(), "a refused create must not reach the orchestrator")
}

// The SDK compute client creates, gets and lists VMs over MCP and reads back
// what the gRPC ComputeService answers (#704).
func TestVMLifecycleParity_SDKOverMCP(t *testing.T) {
	ctx := context.Background()
	provider, svc, _ := seededVMPair()
	client := dialComputeMCP(t, provider, svc)

	config := &platformv1.VMConfig{Name: "vm-9", Memory: &platformv1.MemoryConfig{SizeMb: 2048}}
	created, err := client.CreateVM(ctx, config, false)
	require.NoError(t, err)
	wantCreated, err := svc.CreateVM(ctx, &platformv1.CreateVMRequest{Config: config})
	require.NoError(t, err)
	assert.True(t, proto.Equal(wantCreated.GetVm(), created), "created = %v, want %v", created, wantCreated.GetVm())

	got, err := client.GetVM(ctx, "vm-1")
	require.NoError(t, err)
	wantGot, err := svc.GetVM(ctx, &platformv1.GetVMRequest{Id: "vm-1"})
	require.NoError(t, err)
	assert.True(t, proto.Equal(wantGot.GetVm(), got), "got = %v, want %v", got, wantGot.GetVm())

	listed, _, err := client.ListVMs(ctx, &platformv1.ListVMsRequest{})
	require.NoError(t, err)
	wantListed, err := svc.ListVMs(ctx, &platformv1.ListVMsRequest{})
	require.NoError(t, err)
	require.Len(t, listed, len(wantListed.GetVms()))
	for i, vm := range wantListed.GetVms() {
		assert.True(t, proto.Equal(vm, listed[i]), "listed[%d] = %v, want %v", i, listed[i], vm)
	}
}

func TestVMLifecycleParity_UnknownVM(t *testing.T) {
	notFound := func(context.Context, string) error { return fmt.Errorf("lookup: %w", compute.ErrInstanceNotFound) }
	for _, call := range vmLifecycleCalls {
		if call.name == "vm_create" || call.name == "vm_list" {
			continue
		}
		t.Run(call.name, func(t *testing.T) {
			provider, svc, orch := newComputeParityPair()
			orch.startFunc, orch.stopFunc, orch.deleteFunc = notFound, notFound, notFound
			orch.runStateFunc = notFound

			_, mcpErr := call.mcp(provider, "vm-missing")
			_, grpcErr := call.grpc(svc, "vm-missing")
			assertSameClass(t, codes.NotFound, mcpErr, grpcErr)
		})
	}
}

func TestVMLifecycleParity_InvalidInput(t *testing.T) {
	for _, call := range vmLifecycleCalls {
		if call.name == "vm_list" {
			continue
		}
		t.Run(call.name+" empty", func(t *testing.T) {
			provider, svc, _ := newComputeParityPair()
			_, mcpErr := call.mcp(provider, "")
			_, grpcErr := call.grpc(svc, "")
			assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
		})
	}

	t.Run("orchestrator refuses the id", func(t *testing.T) {
		provider, svc, orch := newComputeParityPair()
		orch.startFunc = func(context.Context, string) error { return compute.ErrInvalidInstanceID }
		_, mcpErr := runVMTool(provider, "vm_start", vmByID("bad/id"))
		_, grpcErr := svc.StartVM(context.Background(), &platformv1.StartVMRequest{Id: "bad/id"})
		assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
	})
}

// Suspending a stopped VM or resuming a running one is a FailedPrecondition
// on both transports, as the orchestrator's wrong-state refusal is.
func TestVMLifecycleParity_WrongState(t *testing.T) {
	for _, sentinel := range []error{compute.ErrInstanceNotRunning, compute.ErrInstanceNotSuspended} {
		for _, call := range vmLifecycleCalls {
			if call.name != "vm_suspend" && call.name != "vm_resume" {
				continue
			}
			t.Run(call.name+" "+sentinel.Error(), func(t *testing.T) {
				provider, svc, orch := seededVMPair()
				orch.runStateFunc = func(context.Context, string) error {
					return &compute.SentinelCauseError{Sentinel: sentinel, Cause: &compute.MessageError{Msg: "wrong state"}}
				}
				_, mcpErr := call.mcp(provider, "vm-1")
				_, grpcErr := call.grpc(svc, "vm-1")
				assertSameClass(t, codes.FailedPrecondition, mcpErr, grpcErr)
			})
		}
	}
}

func TestVMLifecycleParity_NoOrchestrator(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	svc := NewComputeGRPCService(logging.DefaultLogger(), nil)
	for _, call := range vmLifecycleCalls {
		t.Run(call.name, func(t *testing.T) {
			_, mcpErr := call.mcp(provider, "vm-1")
			_, grpcErr := call.grpc(svc, "vm-1")
			assertSameClass(t, codes.FailedPrecondition, mcpErr, grpcErr)
		})
	}
}

// An orchestrator failure vmOpsErrToStatus does not know stays Internal and
// keeps its "failed to <op> VM" message.
func TestVMLifecycleStatus(t *testing.T) {
	err := vmLifecycleStatus("start", errors.New("qemu exited"))
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "failed to start VM: qemu exited", status.Convert(err).Message())

	err = vmLifecycleStatus("delete", fmt.Errorf("vm-2: %w", compute.ErrInstanceNotFound))
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "failed to delete VM: vm-2: instance not found", status.Convert(err).Message())
}

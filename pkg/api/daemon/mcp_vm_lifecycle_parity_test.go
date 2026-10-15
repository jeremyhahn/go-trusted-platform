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

// MCP-vs-gRPC parity for the seven VM lifecycle tools (#304, #317): each MCP
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
// gRPC against the same orchestrator state.
type vmLifecycleCall struct {
	name string
	mcp  func(*MCPServiceProvider, string) (interface{}, error)
	grpc func(*ComputeGRPCService, string) (proto.Message, error)
}

// vmLifecycleCalls are the seven tools and their RPCs. vm_create takes the
// id as the VM name; vm_list ignores it.
var vmLifecycleCalls = []vmLifecycleCall{
	{
		"vm_create",
		func(p *MCPServiceProvider, id string) (interface{}, error) {
			return p.VMCreate(context.Background(), mcp.VMCreateSpec{Name: id})
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.CreateVM(context.Background(), &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: id}})
		},
	},
	{
		"vm_list",
		func(p *MCPServiceProvider, _ string) (interface{}, error) {
			return p.VMList(context.Background())
		},
		func(s *ComputeGRPCService, _ string) (proto.Message, error) {
			return s.ListVMs(context.Background(), &platformv1.ListVMsRequest{})
		},
	},
	{
		"vm_get",
		func(p *MCPServiceProvider, id string) (interface{}, error) {
			return p.VMGet(context.Background(), id)
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.GetVM(context.Background(), &platformv1.GetVMRequest{Id: id})
		},
	},
	{
		"vm_delete",
		func(p *MCPServiceProvider, id string) (interface{}, error) {
			return p.VMDelete(context.Background(), id)
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.DeleteVM(context.Background(), &platformv1.DeleteVMRequest{Id: id})
		},
	},
	{
		"vm_start",
		func(p *MCPServiceProvider, id string) (interface{}, error) {
			return p.VMStart(context.Background(), id)
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.StartVM(context.Background(), &platformv1.StartVMRequest{Id: id})
		},
	},
	{
		"vm_stop",
		func(p *MCPServiceProvider, id string) (interface{}, error) {
			return p.VMStop(context.Background(), id)
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.StopVM(context.Background(), &platformv1.StopVMRequest{Id: id})
		},
	},
	{
		"vm_reboot",
		func(p *MCPServiceProvider, id string) (interface{}, error) {
			return p.VMReboot(context.Background(), id)
		},
		func(s *ComputeGRPCService, id string) (proto.Message, error) {
			return s.RebootVM(context.Background(), &platformv1.RebootVMRequest{Id: id})
		},
	},
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
			got, ok := mcpResult.(json.RawMessage)
			require.True(t, ok, "MCP result is %T, want json.RawMessage", mcpResult)
			assert.JSONEq(t, string(want), string(got))
		})
	}
}

func TestVMLifecycleParity_CreateBuildsTheSameProfile(t *testing.T) {
	memory, cpus := uint64(4096), uint32(2)
	spec := mcp.VMCreateSpec{Name: "vm-9", MemoryMB: &memory, CPUs: &cpus, TPMEnabled: true, SecureBoot: true}
	req := &platformv1.CreateVMRequest{Config: &platformv1.VMConfig{
		Name:       "vm-9",
		Memory:     &platformv1.MemoryConfig{SizeMb: memory},
		Cpu:        &platformv1.CPUConfig{Cores: cpus},
		Tpm:        &platformv1.TPMConfig{Enabled: true, Version: platformv1.TPMVersion_TPM_VERSION_2_0},
		SecureBoot: true,
	}}

	provider, svc, orch := seededVMPair()
	var models []string
	created := orch.createFunc
	orch.createFunc = func(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
		models = append(models, profile.Model)
		return created(ctx, profile)
	}

	_, err := provider.VMCreate(context.Background(), spec)
	require.NoError(t, err)
	_, err = svc.CreateVM(context.Background(), req)
	require.NoError(t, err)

	require.Len(t, models, 2)
	assert.Equal(t, "vm:memory=4096,cpus=2,tpm=true,secureboot=true", models[1])
	assert.Equal(t, models[1], models[0], "MCP must hand the orchestrator what gRPC does")
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
		_, mcpErr := provider.VMStart(context.Background(), "bad/id")
		_, grpcErr := svc.StartVM(context.Background(), &platformv1.StartVMRequest{Id: "bad/id"})
		assertSameClass(t, codes.InvalidArgument, mcpErr, grpcErr)
	})
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

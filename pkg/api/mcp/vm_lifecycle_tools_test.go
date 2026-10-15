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

package mcp

import (
	"context"
	"errors"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmComputeStub is a gRPC ComputeService servicer that records the request
// each VM lifecycle method was given and answers err when set.
type vmComputeStub struct {
	platformv1.UnimplementedComputeServiceServer
	method  string
	request proto.Message
	err     error
}

func (s *vmComputeStub) record(method string, request proto.Message) error {
	s.method, s.request = method, request
	return s.err
}

func (s *vmComputeStub) CreateVM(_ context.Context, req *platformv1.CreateVMRequest) (*platformv1.CreateVMResponse, error) {
	if err := s.record("CreateVM", req); err != nil {
		return nil, err
	}
	return &platformv1.CreateVMResponse{Vm: &platformv1.VM{Id: "vm-1", Config: req.GetConfig()}}, nil
}

func (s *vmComputeStub) ListVMs(_ context.Context, req *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	if err := s.record("ListVMs", req); err != nil {
		return nil, err
	}
	return &platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1"}}}, nil
}

func (s *vmComputeStub) GetVM(_ context.Context, req *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	if err := s.record("GetVM", req); err != nil {
		return nil, err
	}
	return &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: req.GetId(), State: platformv1.VMState_VM_STATE_PAUSED}}, nil
}

func (s *vmComputeStub) DeleteVM(_ context.Context, req *platformv1.DeleteVMRequest) (*platformv1.DeleteVMResponse, error) {
	return &platformv1.DeleteVMResponse{Status: &platformv1.Status{Success: true}}, s.record("DeleteVM", req)
}

func (s *vmComputeStub) StartVM(_ context.Context, req *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	return &platformv1.StartVMResponse{Status: &platformv1.Status{Success: true}}, s.record("StartVM", req)
}

func (s *vmComputeStub) StopVM(_ context.Context, req *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	return &platformv1.StopVMResponse{Status: &platformv1.Status{Success: true}}, s.record("StopVM", req)
}

func (s *vmComputeStub) RebootVM(_ context.Context, req *platformv1.RebootVMRequest) (*platformv1.RebootVMResponse, error) {
	return &platformv1.RebootVMResponse{Status: &platformv1.Status{Success: true}}, s.record("RebootVM", req)
}

func (s *vmComputeStub) SuspendVM(_ context.Context, req *platformv1.SuspendVMRequest) (*platformv1.SuspendVMResponse, error) {
	return &platformv1.SuspendVMResponse{Status: &platformv1.Status{Success: true}}, s.record("SuspendVM", req)
}

func (s *vmComputeStub) ResumeVM(_ context.Context, req *platformv1.ResumeVMRequest) (*platformv1.ResumeVMResponse, error) {
	return &platformv1.ResumeVMResponse{Status: &platformv1.Status{Success: true}}, s.record("ResumeVM", req)
}

// vmComputeProvider is a ComputeProvider serving server.
type vmComputeProvider struct {
	*mockServiceProvider
	server platformv1.ComputeServiceServer
}

func (p *vmComputeProvider) ComputeServiceServer() platformv1.ComputeServiceServer {
	return p.server
}

func newVMLifecycleRegistry() (*ToolRegistry, *vmComputeStub) {
	stub := &vmComputeStub{}
	provider := &vmComputeProvider{mockServiceProvider: newMockServiceProvider(), server: stub}
	return NewToolRegistry(provider, newTestLogger()), stub
}

// vmLifecycleCase is one VM lifecycle tool called with every field of its
// request, and the request the gRPC servicer must receive.
type vmLifecycleCase struct {
	tool   string
	method string
	args   map[string]interface{}
	want   proto.Message
}

// vmLifecycleCases set every request field; JSON numbers arrive as float64,
// as they do off the wire.
var vmLifecycleCases = []vmLifecycleCase{
	{
		tool:   "vm_create",
		method: "CreateVM",
		args: map[string]interface{}{
			"config": map[string]interface{}{
				"name":        "vm-1",
				"description": "test VM",
				"firmware":    "FIRMWARE_TYPE_UEFI",
				"cpu":         map[string]interface{}{"cores": float64(4)},
				"memory":      map[string]interface{}{"size_mb": float64(2048)},
				"disks":       []interface{}{map[string]interface{}{"size_gb": float64(20), "bootable": true}},
				"tpm":         map[string]interface{}{"enabled": true},
				"secure_boot": true,
				"labels":      map[string]interface{}{"env": "test"},
			},
			"start": true,
		},
		want: &platformv1.CreateVMRequest{
			Config: &platformv1.VMConfig{
				Name:        "vm-1",
				Description: "test VM",
				Firmware:    platformv1.FirmwareType_FIRMWARE_TYPE_UEFI,
				Cpu:         &platformv1.CPUConfig{Cores: 4},
				Memory:      &platformv1.MemoryConfig{SizeMb: 2048},
				Disks:       []*platformv1.DiskConfig{{SizeGb: 20, Bootable: true}},
				Tpm:         &platformv1.TPMConfig{Enabled: true},
				SecureBoot:  true,
				Labels:      map[string]string{"env": "test"},
			},
			Start: true,
		},
	},
	{
		tool:   "vm_list",
		method: "ListVMs",
		args: map[string]interface{}{
			"selector":   map[string]interface{}{"match_labels": map[string]interface{}{"env": "test"}},
			"pagination": map[string]interface{}{"page": float64(2), "page_size": float64(10)},
			"states":     []interface{}{"VM_STATE_RUNNING", "VM_STATE_PAUSED"},
		},
		want: &platformv1.ListVMsRequest{
			Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"env": "test"}},
			Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 10},
			States:     []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING, platformv1.VMState_VM_STATE_PAUSED},
		},
	},
	{
		tool:   "vm_get",
		method: "GetVM",
		args:   map[string]interface{}{"id": "vm-7"},
		want:   &platformv1.GetVMRequest{Id: "vm-7"},
	},
	{
		tool:   "vm_delete",
		method: "DeleteVM",
		args:   map[string]interface{}{"id": "vm-7", "delete_disks": true},
		want:   &platformv1.DeleteVMRequest{Id: "vm-7", DeleteDisks: true},
	},
	{
		tool:   "vm_start",
		method: "StartVM",
		args:   map[string]interface{}{"id": "vm-7"},
		want:   &platformv1.StartVMRequest{Id: "vm-7"},
	},
	{
		tool:   "vm_stop",
		method: "StopVM",
		args:   map[string]interface{}{"id": "vm-7", "force": true, "timeout_seconds": float64(30)},
		want:   &platformv1.StopVMRequest{Id: "vm-7", Force: true, TimeoutSeconds: 30},
	},
	{
		tool:   "vm_reboot",
		method: "RebootVM",
		args:   map[string]interface{}{"id": "vm-7", "force": true},
		want:   &platformv1.RebootVMRequest{Id: "vm-7", Force: true},
	},
	{
		tool:   "vm_suspend",
		method: "SuspendVM",
		args:   map[string]interface{}{"id": "vm-7"},
		want:   &platformv1.SuspendVMRequest{Id: "vm-7"},
	},
	{
		tool:   "vm_resume",
		method: "ResumeVM",
		args:   map[string]interface{}{"id": "vm-7"},
		want:   &platformv1.ResumeVMRequest{Id: "vm-7"},
	},
}

func TestVMLifecycleToolsCarryTheFullRequest(t *testing.T) {
	for _, tc := range vmLifecycleCases {
		t.Run(tc.tool, func(t *testing.T) {
			registry, stub := newVMLifecycleRegistry()
			if _, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args); err != nil {
				t.Fatalf("ExecuteTool: %v", err)
			}
			if stub.method != tc.method {
				t.Fatalf("servicer got %s, want %s", stub.method, tc.method)
			}
			if !proto.Equal(stub.request, tc.want) {
				t.Errorf("request = %v, want %v", stub.request, tc.want)
			}
		})
	}
}

func TestVMLifecycleToolsRefuseBadArguments(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"flat create arguments", "vm_create", map[string]interface{}{"name": "vm-1", "memory": float64(1024)}},
		{"unknown config field", "vm_create", map[string]interface{}{"config": map[string]interface{}{"name": "vm-1", "cpus": float64(2)}}},
		{"unknown firmware", "vm_create", map[string]interface{}{"config": map[string]interface{}{"name": "vm-1", "firmware": "UEFI"}}},
		{"negative memory", "vm_create", map[string]interface{}{"config": map[string]interface{}{"name": "vm-1", "memory": map[string]interface{}{"size_mb": float64(-1)}}}},
		{"unknown state", "vm_list", map[string]interface{}{"states": []interface{}{"RUNNING"}}},
		{"numeric id", "vm_get", map[string]interface{}{"id": float64(7)}},
		{"fallback vm_id name", "vm_start", map[string]interface{}{"vm_id": "vm-7"}},
		{"timeout beyond uint32", "vm_stop", map[string]interface{}{"id": "vm-7", "timeout_seconds": float64(1 << 32)}},
		{"force as a string", "vm_reboot", map[string]interface{}{"id": "vm-7", "force": "yes"}},
		{"delete_disks as a number", "vm_delete", map[string]interface{}{"id": "vm-7", "delete_disks": float64(1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry, stub := newVMLifecycleRegistry()
			_, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args)
			var invalid ErrInvalidArgument
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Errorf("class = %s, want InvalidArgument", got)
			}
			if stub.method != "" {
				t.Errorf("servicer reached with %s despite bad arguments", stub.method)
			}
		})
	}
}

func TestVMLifecycleToolsAnswerTheResponse(t *testing.T) {
	registry, _ := newVMLifecycleRegistry()
	result, err := registry.ExecuteTool(context.Background(), "vm_get", map[string]interface{}{"id": "vm-7"})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	reply, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result = %T, want the protojson response as a map", result)
	}
	vm, ok := reply["vm"].(map[string]interface{})
	if !ok || vm["id"] != "vm-7" || vm["state"] != "VM_STATE_PAUSED" {
		t.Errorf("reply = %v, want vm vm-7 in VM_STATE_PAUSED", reply)
	}
}

func TestVMLifecycleToolsPassServerErrorsOn(t *testing.T) {
	notFound := status.Error(codes.NotFound, "VM not found")
	for _, tc := range vmLifecycleCases {
		t.Run(tc.tool, func(t *testing.T) {
			registry, stub := newVMLifecycleRegistry()
			stub.err = notFound
			if _, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args); !errors.Is(err, notFound) {
				t.Errorf("err = %v, want the servicer's error", err)
			}
		})
	}
}

func TestVMLifecycleToolsWithoutServerAreNotConfigured(t *testing.T) {
	registries := map[string]*ToolRegistry{
		"no compute provider": NewToolRegistry(newMockServiceProvider(), newTestLogger()),
		"nil servicer":        NewToolRegistry(&vmComputeProvider{mockServiceProvider: newMockServiceProvider()}, newTestLogger()),
	}
	for name, registry := range registries {
		for _, tc := range vmLifecycleCases {
			if _, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args); !errors.Is(err, ErrVMComputeNotConfigured) {
				t.Errorf("%s: %s: err = %v, want ErrVMComputeNotConfigured", name, tc.tool, err)
			}
		}
	}
}

func TestVMLifecycleToolSchemasAreTheRequests(t *testing.T) {
	schemas := map[string]map[string]interface{}{}
	for _, tool := range NewToolRegistry(nil, newTestLogger()).ListTools() {
		schemas[tool.Name] = tool.InputSchema
	}
	required := map[string][]string{"vm_create": {"config"}, "vm_list": nil}
	for _, tc := range vmLifecycleCases {
		t.Run(tc.tool, func(t *testing.T) {
			schema, ok := schemas[tc.tool]
			if !ok {
				t.Fatalf("%s is not registered", tc.tool)
			}
			properties, _ := schema["properties"].(map[string]interface{})
			fields := tc.want.ProtoReflect().Descriptor().Fields()
			if len(properties) != fields.Len() {
				t.Errorf("schema has %d properties, request has %d fields", len(properties), fields.Len())
			}
			for i := range fields.Len() {
				if _, ok := properties[string(fields.Get(i).Name())]; !ok {
					t.Errorf("schema lacks request field %s", fields.Get(i).Name())
				}
			}
			want, ok := required[tc.tool]
			if !ok {
				want = []string{"id"}
			}
			got, _ := schema["required"].([]string)
			if !slices.Equal(got, want) {
				t.Errorf("required = %v, want %v", got, want)
			}
		})
	}
}

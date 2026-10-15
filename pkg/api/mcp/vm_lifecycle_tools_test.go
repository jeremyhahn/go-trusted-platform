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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// vmLifecycleStub is a VMLifecycleProvider that records what it was asked
// and answers err when set.
type vmLifecycleStub struct {
	*mockServiceProvider
	lastOp   string
	lastID   string
	lastSpec VMCreateSpec
	err      error
}

func (s *vmLifecycleStub) answer(op, id string) (interface{}, error) {
	s.lastOp, s.lastID = op, id
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{"op": op}, nil
}

func (s *vmLifecycleStub) VMCreate(_ context.Context, spec VMCreateSpec) (interface{}, error) {
	s.lastSpec = spec
	return s.answer("VMCreate", "")
}

func (s *vmLifecycleStub) VMList(context.Context) (interface{}, error) {
	return s.answer("VMList", "")
}

func (s *vmLifecycleStub) VMGet(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMGet", id)
}

func (s *vmLifecycleStub) VMDelete(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMDelete", id)
}

func (s *vmLifecycleStub) VMStart(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMStart", id)
}

func (s *vmLifecycleStub) VMStop(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMStop", id)
}

func (s *vmLifecycleStub) VMReboot(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMReboot", id)
}

func (s *vmLifecycleStub) VMSuspend(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMSuspend", id)
}

func (s *vmLifecycleStub) VMResume(_ context.Context, id string) (interface{}, error) {
	return s.answer("VMResume", id)
}

func newVMLifecycleRegistry() (*ToolRegistry, *vmLifecycleStub) {
	stub := &vmLifecycleStub{mockServiceProvider: newMockServiceProvider()}
	return NewToolRegistry(stub, newTestLogger()), stub
}

// vmByIDTools are the lifecycle tools that name one VM by its "id".
var vmByIDTools = map[string]string{
	"vm_get":     "VMGet",
	"vm_delete":  "VMDelete",
	"vm_start":   "VMStart",
	"vm_stop":    "VMStop",
	"vm_reboot":  "VMReboot",
	"vm_suspend": "VMSuspend",
	"vm_resume":  "VMResume",
}

func TestVMByIDToolsPassTheID(t *testing.T) {
	for tool, op := range vmByIDTools {
		t.Run(tool, func(t *testing.T) {
			registry, stub := newVMLifecycleRegistry()
			if _, err := registry.ExecuteTool(context.Background(), tool, map[string]interface{}{"id": "vm-7"}); err != nil {
				t.Fatalf("ExecuteTool: %v", err)
			}
			if stub.lastOp != op || stub.lastID != "vm-7" {
				t.Errorf("provider got %s(%q), want %s(\"vm-7\")", stub.lastOp, stub.lastID, op)
			}
		})
	}
}

func TestVMByIDToolsRequireTheID(t *testing.T) {
	for tool := range vmByIDTools {
		t.Run(tool, func(t *testing.T) {
			registry, stub := newVMLifecycleRegistry()
			_, err := registry.ExecuteTool(context.Background(), tool, map[string]interface{}{})
			if !errors.Is(err, ErrVMIDRequired) {
				t.Fatalf("err = %v, want ErrVMIDRequired", err)
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Errorf("class = %s, want InvalidArgument", got)
			}
			if stub.lastOp != "" {
				t.Errorf("provider reached with %s despite the missing id", stub.lastOp)
			}
		})
	}
}

func TestVMLifecycleToolsWithoutProviderAreNotConfigured(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	args := map[string]interface{}{"id": "vm-1", "name": "vm-1"}
	for _, tool := range []string{"vm_create", "vm_list", "vm_get", "vm_delete", "vm_start", "vm_stop", "vm_reboot", "vm_suspend", "vm_resume"} {
		if _, err := registry.ExecuteTool(context.Background(), tool, args); !errors.Is(err, ErrVMComputeNotConfigured) {
			t.Errorf("%s: err = %v, want ErrVMComputeNotConfigured", tool, err)
		}
	}
}

func TestVMLifecycleToolsPassProviderErrorsOn(t *testing.T) {
	notFound := status.Error(codes.NotFound, "VM not found")
	args := map[string]interface{}{"id": "vm-1", "name": "vm-1"}
	for _, tool := range []string{"vm_create", "vm_list", "vm_get", "vm_delete", "vm_start", "vm_stop", "vm_reboot", "vm_suspend", "vm_resume"} {
		registry, stub := newVMLifecycleRegistry()
		stub.err = notFound
		if _, err := registry.ExecuteTool(context.Background(), tool, args); !errors.Is(err, notFound) {
			t.Errorf("%s: err = %v, want the provider's error", tool, err)
		}
	}
}

func TestVMListReachesTheProvider(t *testing.T) {
	registry, stub := newVMLifecycleRegistry()
	if _, err := registry.ExecuteTool(context.Background(), "vm_list", map[string]interface{}{}); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if stub.lastOp != "VMList" {
		t.Errorf("provider got %q, want VMList", stub.lastOp)
	}
}

func TestVMCreateSpecFromArguments(t *testing.T) {
	registry, stub := newVMLifecycleRegistry()
	_, err := registry.ExecuteTool(context.Background(), "vm_create", map[string]interface{}{
		"name":        "vm-1",
		"memory":      float64(2048),
		"cpus":        float64(4),
		"tpm_enabled": true,
		"secure_boot": true,
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	spec := stub.lastSpec
	if spec.Name != "vm-1" || !spec.TPMEnabled || !spec.SecureBoot {
		t.Errorf("spec = %+v, want name vm-1 with TPM and Secure Boot", spec)
	}
	if spec.MemoryMB == nil || *spec.MemoryMB != 2048 {
		t.Errorf("MemoryMB = %v, want 2048", spec.MemoryMB)
	}
	if spec.CPUs == nil || *spec.CPUs != 4 {
		t.Errorf("CPUs = %v, want 4", spec.CPUs)
	}
}

func TestVMCreateSpecLeavesOmittedSizesToTheRPC(t *testing.T) {
	registry, stub := newVMLifecycleRegistry()
	if _, err := registry.ExecuteTool(context.Background(), "vm_create", map[string]interface{}{"name": "vm-1"}); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	spec := stub.lastSpec
	if spec.MemoryMB != nil || spec.CPUs != nil || spec.TPMEnabled || spec.SecureBoot {
		t.Errorf("spec = %+v, want only the name set", spec)
	}
}

func TestVMCreateRefusesBadArguments(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want error
	}{
		{"missing name", map[string]interface{}{"memory": float64(1024)}, ErrVMNameRequired},
		{"negative memory", map[string]interface{}{"name": "vm-1", "memory": float64(-1)}, nil},
		{"negative cpus", map[string]interface{}{"name": "vm-1", "cpus": float64(-1)}, nil},
		{"cpus beyond uint32", map[string]interface{}{"name": "vm-1", "cpus": float64(1 << 32)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry, stub := newVMLifecycleRegistry()
			_, err := registry.ExecuteTool(context.Background(), "vm_create", tc.args)
			if err == nil {
				t.Fatal("ExecuteTool succeeded, want a refusal")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Errorf("class = %s, want InvalidArgument", got)
			}
			if stub.lastOp != "" {
				t.Errorf("provider reached with %s despite bad arguments", stub.lastOp)
			}
		})
	}
}

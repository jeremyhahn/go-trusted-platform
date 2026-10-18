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
	"math"
)

// VMCreateSpec is the vm_create request: the fields ComputeService.CreateVM
// reads from its VMConfig. A nil MemoryMB or CPUs leaves the RPC's default.
type VMCreateSpec struct {
	Name       string
	MemoryMB   *uint64
	CPUs       *uint32
	TPMEnabled bool
	SecureBoot bool
}

// VMLifecycleProvider serves the VM lifecycle tools that have a gRPC
// ComputeService twin (#304, #317). Each method answers with its RPC's
// result and error class.
type VMLifecycleProvider interface {
	// VMCreate creates a VM, as CreateVM does.
	VMCreate(ctx context.Context, spec VMCreateSpec) (interface{}, error)

	// VMList lists every VM, as ListVMs does.
	VMList(ctx context.Context) (interface{}, error)

	// VMGet returns one VM, as GetVM does.
	VMGet(ctx context.Context, vmID string) (interface{}, error)

	// VMDelete deletes a VM, as DeleteVM does.
	VMDelete(ctx context.Context, vmID string) (interface{}, error)

	// VMStart starts a VM, as StartVM does.
	VMStart(ctx context.Context, vmID string) (interface{}, error)

	// VMStop stops a VM, as StopVM does.
	VMStop(ctx context.Context, vmID string) (interface{}, error)

	// VMReboot stops then starts a VM, as RebootVM does.
	VMReboot(ctx context.Context, vmID string) (interface{}, error)
}

// vmLifecycleProvider returns the VMLifecycleProvider the configured service
// implements, or nil when it implements none.
func (r *ToolRegistry) vmLifecycleProvider() VMLifecycleProvider {
	if p, ok := r.service.(VMLifecycleProvider); ok {
		return p
	}
	return nil
}

// vmLifecycleByID is the shape of every lifecycle call that names one VM.
type vmLifecycleByID func(VMLifecycleProvider, context.Context, string) (interface{}, error)

// executeVMByID resolves the provider and the tool's "id" argument, then
// makes the call.
func (r *ToolRegistry) executeVMByID(ctx context.Context, args map[string]interface{}, call vmLifecycleByID) (interface{}, error) {
	p := r.vmLifecycleProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	id := getString(args, "id")
	if id == "" {
		return nil, ErrVMIDRequired
	}
	return call(p, ctx, id)
}

func (r *ToolRegistry) executeVMGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMByID(ctx, args, VMLifecycleProvider.VMGet)
}

func (r *ToolRegistry) executeVMDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMByID(ctx, args, VMLifecycleProvider.VMDelete)
}

func (r *ToolRegistry) executeVMStart(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMByID(ctx, args, VMLifecycleProvider.VMStart)
}

func (r *ToolRegistry) executeVMStop(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMByID(ctx, args, VMLifecycleProvider.VMStop)
}

func (r *ToolRegistry) executeVMReboot(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMByID(ctx, args, VMLifecycleProvider.VMReboot)
}

func (r *ToolRegistry) executeVMList(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.vmLifecycleProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	return p.VMList(ctx)
}

func (r *ToolRegistry) executeVMCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmLifecycleProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	spec, err := vmCreateSpec(args)
	if err != nil {
		return nil, err
	}
	return p.VMCreate(ctx, spec)
}

// vmCreateSpec reads the vm_create arguments. The name is required, and a
// memory or cpus value the RPC's unsigned fields cannot carry is refused.
func vmCreateSpec(args map[string]interface{}) (VMCreateSpec, error) {
	spec := VMCreateSpec{
		Name:       getString(args, "name"),
		TPMEnabled: getBool(args, "tpm_enabled"),
		SecureBoot: getBool(args, "secure_boot"),
	}
	if spec.Name == "" {
		return VMCreateSpec{}, ErrVMNameRequired
	}
	if _, ok := args["memory"]; ok {
		memory := getInt64(args, "memory")
		if memory < 0 {
			return VMCreateSpec{}, ErrInvalidArgument{Msg: "memory must not be negative"}
		}
		memoryMB := uint64(memory)
		spec.MemoryMB = &memoryMB
	}
	if _, ok := args["cpus"]; ok {
		cpus := getInt64(args, "cpus")
		if cpus < 0 || cpus > math.MaxUint32 {
			return VMCreateSpec{}, ErrInvalidArgument{Msg: "cpus must be between 0 and 4294967295"}
		}
		cores := uint32(cpus)
		spec.CPUs = &cores
	}
	return spec, nil
}

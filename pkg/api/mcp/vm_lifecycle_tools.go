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
	"maps"
	"slices"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// VM lifecycle tool wiring
// =============================================================================
//
// Every VM lifecycle tool has one gRPC ComputeService twin (#304, #317, #704).
// A tool's arguments are the gRPC request in protojson form (proto field
// names, enums by name, 64-bit integers as JSON strings) and its result is
// the gRPC response in the same form. Each tool calls the gRPC ComputeService
// servicer, so it validates, answers and fails exactly as gRPC does. The
// permission each tool requires is in authz.go.

// ComputeProvider is implemented by a ServiceProvider that serves the gRPC
// ComputeService. The VM lifecycle tools call that servicer.
type ComputeProvider interface {
	// ComputeServiceServer returns the gRPC ComputeService servicer, or nil
	// while no compute service is wired.
	ComputeServiceServer() platformv1.ComputeServiceServer
}

// vmLifecycleTool is one VM lifecycle tool and the gRPC method it serves.
type vmLifecycleTool struct {
	description string
	binding     grpcToolBinding[platformv1.ComputeServiceServer]
}

// vmLifecycleTools are the VM lifecycle tools bound to the gRPC
// ComputeService.
var vmLifecycleTools = map[string]vmLifecycleTool{
	"vm_create": {
		description: "Create a VM from config (name required; firmware, cpu, memory, disks, networks, tpm, secure_boot, labels); start boots it once created",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.CreateVM, "config"),
	},
	"vm_list": {
		description: "List VMs, filtered by selector labels and states, one page at a time",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.ListVMs),
	},
	"vm_get": {
		description: "Get a VM's configuration and state by id",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.GetVM, "id"),
	},
	"vm_delete": {
		description: "Delete a VM by id; delete_disks also removes its disks",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.DeleteVM, "id"),
	},
	"vm_start": {
		description: "Start a stopped VM",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.StartVM, "id"),
	},
	"vm_stop": {
		description: "Stop a running VM; force skips the graceful shutdown and timeout_seconds bounds it",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.StopVM, "id"),
	},
	"vm_reboot": {
		description: "Reboot a running VM; force resets it without a graceful shutdown",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.RebootVM, "id"),
	},
	"vm_suspend": {
		description: "Suspend a running VM: pause it in memory",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.SuspendVM, "id"),
	},
	"vm_resume": {
		description: "Resume a suspended VM",
		binding:     grpcToolMethod(platformv1.ComputeServiceServer.ResumeVM, "id"),
	},
}

// registerVMLifecycleTools registers the VM lifecycle tools.
func (r *ToolRegistry) registerVMLifecycleTools() {
	for _, name := range slices.Sorted(maps.Keys(vmLifecycleTools)) {
		tool := vmLifecycleTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// computeServiceServer is the gRPC ComputeService servicer the VM lifecycle
// tools call, or nil while the service provider serves none.
func (r *ToolRegistry) computeServiceServer() platformv1.ComputeServiceServer {
	if provider, ok := r.service.(ComputeProvider); ok {
		return provider.ComputeServiceServer()
	}
	return nil
}

// dispatchVMLifecycleTool runs a VM lifecycle tool. handled is false when
// name is not a VM lifecycle tool, so the caller tries the next dispatcher.
func (r *ToolRegistry) dispatchVMLifecycleTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := vmLifecycleTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.computeServiceServer()
	if server == nil {
		return nil, true, ErrVMComputeNotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}

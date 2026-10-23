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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Operational VM tool wiring (metrics, disk hotplug/unplug/resize, logs
// snapshot, migrate)
// =============================================================================
//
// These tools mirror the platform.v1 ComputeService operational VM surface
// (GetVMMetrics / AttachDisk / DetachDisk / ResizeDisk / GetVMLogs / MigrateVM)
// so AI/LLM clients can drive them over MCP. Routing uses a map-based
// dispatcher (O(1) lookup per project conventions), matching the VM
// snapshot/attestation dispatcher in vm_tools_exec.go.
//
// MCP is a request/response transport: the interactive VM console
// (AttachVMConsole / SendVMConsoleInput) and log-FOLLOW are streaming-only and
// are intentionally NOT exposed as MCP tools — they are served over gRPC
// (server/bidi streaming) and, for logs, a bounded snapshot is offered here via
// vm_logs (Follow=false, tail-N collected into the single response).

// VMDiskAttachSpec describes a disk to hot-plug via the vm_disk_attach tool.
type VMDiskAttachSpec struct {
	// ID is the caller-facing disk identifier. Empty lets the manager assign one.
	ID string

	// Path is the backing image path. When it does not exist and SizeGB > 0 a
	// qcow2 image of that size is created.
	Path string

	// Bus is the guest bus; only "virtio" supports hotplug. Empty defaults to
	// "virtio".
	Bus string

	// SizeGB is the size for a newly created image, in gibibytes.
	SizeGB uint64

	// Readonly attaches the disk read-only.
	Readonly bool
}

// VMOpsServiceProvider is the optional capability a ServiceProvider implements
// to serve the operational VM tools. It follows the same optional-interface
// pattern used by ContainerOpsServiceProvider so the core ServiceProvider
// interface stays stable while new capabilities are added out-of-band.
// Implementations delegate to the compute orchestrator's canonical
// VMMetricsReader / VMDiskManager / VMLogStreamer / VMMigrator capabilities.
type VMOpsServiceProvider interface {
	// VMMetrics samples a running VM's CPU, memory, disk, and network metrics.
	VMMetrics(ctx context.Context, vmID string) (interface{}, error)

	// VMDiskAttach hot-plugs a disk onto a running VM.
	VMDiskAttach(ctx context.Context, vmID string, spec VMDiskAttachSpec) (interface{}, error)

	// VMDiskDetach unplugs a disk from a running VM.
	VMDiskDetach(ctx context.Context, vmID, diskID string) error

	// VMDiskResize changes a disk's virtual size (online or offline).
	VMDiskResize(ctx context.Context, vmID, diskID string, newSizeGB uint64) error

	// VMLogsSnapshot returns a bounded, non-following snapshot of a VM's serial
	// transcript and QMP lifecycle events (the last tailLines entries).
	VMLogsSnapshot(ctx context.Context, vmID string, tailLines int) (interface{}, error)

	// VMMigrate migrates a VM to destinationHost. When live is false a cold
	// migration is performed; live migration requires shared storage.
	VMMigrate(ctx context.Context, vmID, destinationHost string, live bool, bandwidthMbps uint64) (interface{}, error)
}

// vmOpsProvider returns the VMOpsServiceProvider interface if the configured
// service implements it, or nil when the operational VM tools are unavailable.
func (r *ToolRegistry) vmOpsProvider() VMOpsServiceProvider {
	if p, ok := r.service.(VMOpsServiceProvider); ok {
		return p
	}
	return nil
}

// registerVMOpsTools registers the operational VM tools.
func (r *ToolRegistry) registerVMOpsTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_metrics",
		Description: "Get resource-usage metrics (CPU, memory, disk I/O, network) for a running VM",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id": map[string]interface{}{
					"type":        "string",
					"description": "VM instance ID",
				},
			},
			"required": []string{"vm_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_disk_attach",
		Description: "Hot-plug a virtio disk onto a running VM, optionally creating the backing image",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id":    map[string]interface{}{"type": "string", "description": "VM instance ID"},
				"disk_id":  map[string]interface{}{"type": "string", "description": "Optional caller-facing disk ID"},
				"path":     map[string]interface{}{"type": "string", "description": "Backing image path"},
				"bus":      map[string]interface{}{"type": "string", "description": "Guest bus (only 'virtio' supports hotplug)"},
				"size_gb":  map[string]interface{}{"type": "integer", "description": "Size for a newly created image, in GiB"},
				"readonly": map[string]interface{}{"type": "boolean", "description": "Attach read-only", "default": false},
			},
			"required": []string{"vm_id", "path"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_disk_detach",
		Description: "Unplug a previously attached disk from a running VM",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id":   map[string]interface{}{"type": "string", "description": "VM instance ID"},
				"disk_id": map[string]interface{}{"type": "string", "description": "Disk ID to detach"},
			},
			"required": []string{"vm_id", "disk_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_disk_resize",
		Description: "Resize a VM disk (online via QMP when running, offline via qemu-img when stopped)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id":       map[string]interface{}{"type": "string", "description": "VM instance ID"},
				"disk_id":     map[string]interface{}{"type": "string", "description": "Disk ID (or boot-disk alias)"},
				"new_size_gb": map[string]interface{}{"type": "integer", "description": "New virtual size, in GiB"},
			},
			"required": []string{"vm_id", "disk_id", "new_size_gb"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_logs",
		Description: "Get a bounded snapshot of a VM's serial console transcript and lifecycle events (non-following; use gRPC for live follow)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id":      map[string]interface{}{"type": "string", "description": "VM instance ID"},
				"tail_lines": map[string]interface{}{"type": "integer", "description": "Limit to the last N entries (0 = all backlog)", "default": 100},
			},
			"required": []string{"vm_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "vm_migrate",
		Description: "Migrate a VM to another host. Cold migration is always available; live migration requires shared storage. Transport is mTLS-secured.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vm_id":            map[string]interface{}{"type": "string", "description": "VM instance ID"},
				"destination_host": map[string]interface{}{"type": "string", "description": "host:port of the destination platformd gRPC endpoint"},
				"live":             map[string]interface{}{"type": "boolean", "description": "Perform a live (shared-storage) migration", "default": false},
				"bandwidth_mbps":   map[string]interface{}{"type": "integer", "description": "Optional migration bandwidth cap in Mbps (0 = unlimited)"},
			},
			"required": []string{"vm_id", "destination_host"},
		},
	})
}

// vmOpsToolHandler is the executor signature for operational VM tools.
type vmOpsToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

// vmOpsToolDispatch maps operational VM tool names to executors for O(1)
// routing per project conventions.
var vmOpsToolDispatch = map[string]vmOpsToolHandler{
	"vm_metrics":     (*ToolRegistry).executeVMMetrics,
	"vm_disk_attach": (*ToolRegistry).executeVMDiskAttach,
	"vm_disk_detach": (*ToolRegistry).executeVMDiskDetach,
	"vm_disk_resize": (*ToolRegistry).executeVMDiskResize,
	"vm_logs":        (*ToolRegistry).executeVMLogs,
	"vm_migrate":     (*ToolRegistry).executeVMMigrate,
}

// dispatchVMOpsTool looks up an operational VM tool and invokes it. Returns
// (result, handled, err) so the caller can fall through when handled is false.
func (r *ToolRegistry) dispatchVMOpsTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := vmOpsToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeVMMetrics(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmOpsProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.VMMetrics(ctx, vmID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVMDiskAttach(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmOpsProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	path := getString(args, "path")
	if path == "" {
		return nil, ErrVMDiskPathRequired
	}
	spec := VMDiskAttachSpec{
		ID:       getString(args, "disk_id"),
		Path:     path,
		Bus:      getString(args, "bus"),
		SizeGB:   uint64(getInt64(args, "size_gb")),
		Readonly: getBool(args, "readonly"),
	}
	result, err := p.VMDiskAttach(ctx, vmID, spec)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVMDiskDetach(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmOpsProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	diskID := getString(args, "disk_id")
	if diskID == "" {
		return nil, ErrVMDiskIDRequired
	}
	if err := p.VMDiskDetach(ctx, vmID, diskID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "vm_id": vmID, "disk_id": diskID}, nil
}

func (r *ToolRegistry) executeVMDiskResize(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmOpsProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	diskID := getString(args, "disk_id")
	if diskID == "" {
		return nil, ErrVMDiskIDRequired
	}
	newSize := getInt64(args, "new_size_gb")
	if newSize <= 0 {
		return nil, ErrVMDiskSizeRequired
	}
	if err := p.VMDiskResize(ctx, vmID, diskID, uint64(newSize)); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "vm_id": vmID, "disk_id": diskID, "new_size_gb": newSize}, nil
}

func (r *ToolRegistry) executeVMLogs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmOpsProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.VMLogsSnapshot(ctx, vmID, getInt(args, "tail_lines"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVMMigrate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmOpsProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	dest := getString(args, "destination_host")
	if dest == "" {
		return nil, ErrVMMigrateDestinationRequired
	}
	result, err := p.VMMigrate(ctx, vmID, dest, getBool(args, "live"), uint64(getInt64(args, "bandwidth_mbps")))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// =============================================================================
// Operational VM tool errors
// =============================================================================

// ErrVMDiskPathRequired indicates the disk path argument is missing.
var ErrVMDiskPathRequired = &VMError{Code: "VM_DISK_PATH_REQUIRED", Message: "disk path is required"}

// ErrVMDiskIDRequired indicates the disk ID argument is missing.
var ErrVMDiskIDRequired = &VMError{Code: "VM_DISK_ID_REQUIRED", Message: "disk ID is required"}

// ErrVMDiskSizeRequired indicates the new disk size argument is missing or
// not positive.
var ErrVMDiskSizeRequired = &VMError{Code: "VM_DISK_SIZE_REQUIRED", Message: "new_size_gb must be greater than zero"}

// ErrVMMigrateDestinationRequired indicates the destination host argument is
// missing.
var ErrVMMigrateDestinationRequired = &VMError{Code: "VM_MIGRATE_DESTINATION_REQUIRED", Message: "destination_host is required"}

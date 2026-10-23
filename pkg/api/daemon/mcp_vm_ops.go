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

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// Compile-time proof that MCPServiceProvider satisfies the optional MCP
// VMOpsServiceProvider capability interface (metrics, disk ops, logs snapshot,
// migrate).
var _ mcp.VMOpsServiceProvider = (*MCPServiceProvider)(nil)

// ErrVMMetricsNotSupported is returned when the configured compute orchestrator
// does not provide the VM metrics capability.
type ErrVMMetricsNotSupported struct{}

// Error implements the error interface.
func (e ErrVMMetricsNotSupported) Error() string {
	return "daemon: VM metrics not supported by the configured compute orchestrator"
}

// ErrVMDiskOpsNotSupported is returned when the configured compute orchestrator
// does not provide the VM disk-management capability.
type ErrVMDiskOpsNotSupported struct{}

// Error implements the error interface.
func (e ErrVMDiskOpsNotSupported) Error() string {
	return "daemon: VM disk management not supported by the configured compute orchestrator"
}

// ErrVMLogsNotSupported is returned when the configured compute orchestrator
// does not provide the VM log-streaming capability.
type ErrVMLogsNotSupported struct{}

// Error implements the error interface.
func (e ErrVMLogsNotSupported) Error() string {
	return "daemon: VM logs not supported by the configured compute orchestrator"
}

// ErrVMMigrateNotSupported is returned when the configured compute orchestrator
// does not provide the VM migration capability.
type ErrVMMigrateNotSupported struct{}

// Error implements the error interface.
func (e ErrVMMigrateNotSupported) Error() string {
	return "daemon: VM migration not supported by the configured compute orchestrator"
}

// vmMetricsReader returns the compute orchestrator's VM metrics capability.
func (m *MCPServiceProvider) vmMetricsReader() (compute.VMMetricsReader, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrVMComputeNotAvailable{}
	}
	reader, ok := m.computeOrchestrator.(compute.VMMetricsReader)
	if !ok {
		return nil, ErrVMMetricsNotSupported{}
	}
	return reader, nil
}

// vmDiskManager returns the compute orchestrator's VM disk-management capability.
func (m *MCPServiceProvider) vmDiskManager() (compute.VMDiskManager, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrVMComputeNotAvailable{}
	}
	mgr, ok := m.computeOrchestrator.(compute.VMDiskManager)
	if !ok {
		return nil, ErrVMDiskOpsNotSupported{}
	}
	return mgr, nil
}

// vmLogStreamer returns the compute orchestrator's VM log-streaming capability.
func (m *MCPServiceProvider) vmLogStreamer() (compute.VMLogStreamer, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrVMComputeNotAvailable{}
	}
	streamer, ok := m.computeOrchestrator.(compute.VMLogStreamer)
	if !ok {
		return nil, ErrVMLogsNotSupported{}
	}
	return streamer, nil
}

// vmMigrator returns the compute orchestrator's VM migration capability.
func (m *MCPServiceProvider) vmMigrator() (compute.VMMigrator, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrVMComputeNotAvailable{}
	}
	migrator, ok := m.computeOrchestrator.(compute.VMMigrator)
	if !ok {
		return nil, ErrVMMigrateNotSupported{}
	}
	return migrator, nil
}

// VMMetrics samples a running VM's CPU, memory, disk, and network metrics.
func (m *MCPServiceProvider) VMMetrics(ctx context.Context, vmID string) (interface{}, error) {
	reader, err := m.vmMetricsReader()
	if err != nil {
		return nil, err
	}
	metrics, err := reader.GetVMMetrics(ctx, vmID)
	if err != nil {
		return nil, classifyComputeErr(err, vmOpsErrToStatus)
	}
	return map[string]interface{}{
		"vm_id":               vmID,
		"cpu_usage_percent":   metrics.CPUUsagePercent,
		"memory_used_mb":      metrics.MemoryUsedMB,
		"memory_available_mb": metrics.MemoryAvailableMB,
		"disk_read_bytes":     metrics.DiskReadBytes,
		"disk_write_bytes":    metrics.DiskWriteBytes,
		"network_rx_bytes":    metrics.NetworkRxBytes,
		"network_tx_bytes":    metrics.NetworkTxBytes,
		"uptime_seconds":      metrics.UptimeSeconds,
	}, nil
}

// VMDiskAttach hot-plugs a disk onto a running VM.
func (m *MCPServiceProvider) VMDiskAttach(ctx context.Context, vmID string, spec mcp.VMDiskAttachSpec) (interface{}, error) {
	mgr, err := m.vmDiskManager()
	if err != nil {
		return nil, err
	}
	info, err := mgr.AttachDisk(ctx, vmID, compute.DiskAttachRequest{
		ID:       spec.ID,
		Path:     spec.Path,
		Bus:      spec.Bus,
		SizeGB:   spec.SizeGB,
		Readonly: spec.Readonly,
	})
	if err != nil {
		return nil, classifyComputeErr(err, vmOpsErrToStatus)
	}
	return map[string]interface{}{
		"vm_id":     vmID,
		"disk_id":   info.ID,
		"path":      info.Path,
		"bus":       info.Bus,
		"index":     info.Index,
		"size_gb":   info.SizeGB,
		"node_name": info.NodeName,
		"readonly":  info.Readonly,
	}, nil
}

// VMDiskDetach unplugs a disk from a running VM.
func (m *MCPServiceProvider) VMDiskDetach(ctx context.Context, vmID, diskID string) error {
	mgr, err := m.vmDiskManager()
	if err != nil {
		return err
	}
	return classifyComputeErr(mgr.DetachDisk(ctx, vmID, diskID), vmOpsErrToStatus)
}

// VMDiskResize changes a disk's virtual size.
func (m *MCPServiceProvider) VMDiskResize(ctx context.Context, vmID, diskID string, newSizeGB uint64) error {
	mgr, err := m.vmDiskManager()
	if err != nil {
		return err
	}
	return classifyComputeErr(mgr.ResizeDisk(ctx, vmID, diskID, newSizeGB), vmOpsErrToStatus)
}

// VMLogsSnapshot returns a bounded, non-following snapshot of a VM's serial
// transcript and QMP lifecycle events. MCP is request/response, so the stream
// is drained with Follow=false and the (tail-bounded) backlog is collected into
// the single response.
func (m *MCPServiceProvider) VMLogsSnapshot(ctx context.Context, vmID string, tailLines int) (interface{}, error) {
	streamer, err := m.vmLogStreamer()
	if err != nil {
		return nil, err
	}
	entries := make([]map[string]interface{}, 0, 64)
	sink := func(e compute.LogEntry) error {
		entries = append(entries, map[string]interface{}{
			"timestamp": e.Timestamp.Format(time.RFC3339Nano),
			"level":     e.Level,
			"message":   e.Message,
			"source":    e.Source,
		})
		return nil
	}
	if err := streamer.StreamVMLogs(ctx, vmID, compute.VMLogOptions{Follow: false, TailLines: tailLines}, sink); err != nil {
		return nil, classifyComputeErr(err, vmOpsErrToStatus)
	}
	return map[string]interface{}{
		"vm_id":   vmID,
		"entries": entries,
		"count":   len(entries),
	}, nil
}

// VMMigrate migrates a VM to destinationHost. Cold migration is always
// available; live migration requires shared storage. The transport is
// mTLS-secured by the orchestrator's migration engine.
func (m *MCPServiceProvider) VMMigrate(ctx context.Context, vmID, destinationHost string, live bool, bandwidthMbps uint64) (interface{}, error) {
	migrator, err := m.vmMigrator()
	if err != nil {
		return nil, err
	}
	result, err := migrator.MigrateVM(ctx, vmID, destinationHost, compute.MigrateOptions{
		Live:               live,
		BandwidthLimitMbps: bandwidthMbps,
	})
	if err != nil {
		return nil, classifyComputeErr(err, migrateVMErrToStatus)
	}
	return map[string]interface{}{
		"vm_id":            vmID,
		"destination_host": destinationHost,
		"mode":             string(result.Mode),
		"success":          result.Success,
		"message":          result.Message,
	}, nil
}

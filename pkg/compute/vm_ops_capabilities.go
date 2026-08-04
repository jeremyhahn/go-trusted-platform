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

package compute

import (
	"context"
	"time"
)

// =============================================================================
// VM operational capability interfaces
//
// These are small, single-purpose capability interfaces the protocol surfaces
// type-assert on the compute Orchestrator. Orchestrators that manage QEMU
// virtual machines (QEMUOrchestrator) implement them; container orchestrators
// do not, so protocol surfaces reject the operation with a typed
// capability-not-supported error rather than returning a silent stub.
// =============================================================================

// VMMetrics is a point-in-time sample of a running VM's resource utilization.
// All rates are cumulative-since-boot except CPUUsagePercent, which is sampled
// over a short interval.
type VMMetrics struct {
	// CPUUsagePercent is the VM process CPU utilization sampled over a short
	// interval, expressed as a percentage of a single host core (may exceed
	// 100 for multi-vCPU guests).
	CPUUsagePercent float64 `json:"cpu_usage_percent"`

	// MemoryUsedMB is the resident set size of the VM process in mebibytes.
	MemoryUsedMB uint64 `json:"memory_used_mb"`

	// MemoryAvailableMB is the configured guest memory not currently resident.
	MemoryAvailableMB uint64 `json:"memory_available_mb"`

	// DiskReadBytes is the cumulative bytes read across all block devices.
	DiskReadBytes uint64 `json:"disk_read_bytes"`

	// DiskWriteBytes is the cumulative bytes written across all block devices.
	DiskWriteBytes uint64 `json:"disk_write_bytes"`

	// NetworkRxBytes is the cumulative bytes received by the guest.
	NetworkRxBytes uint64 `json:"network_rx_bytes"`

	// NetworkTxBytes is the cumulative bytes transmitted by the guest.
	NetworkTxBytes uint64 `json:"network_tx_bytes"`

	// UptimeSeconds is the elapsed time since the VM last entered the running
	// state.
	UptimeSeconds uint32 `json:"uptime_seconds"`
}

// VMMetricsReader is the capability interface for sampling live VM resource
// metrics from host primitives (/proc, QMP query-blockstats, host tap
// statistics).
type VMMetricsReader interface {
	// GetVMMetrics samples the running VM's CPU, memory, disk, and network
	// utilization. It requires the instance to be running.
	GetVMMetrics(ctx context.Context, instanceID string) (*VMMetrics, error)
}

// LogEntry is a single VM log line surfaced to a consumer. VM logs are the
// serial console transcript plus synthetic lifecycle events derived from QMP;
// guest-application logs are out of scope (they require a guest agent).
type LogEntry struct {
	// Timestamp is when the entry was observed. Serial transcript lines carry
	// no embedded timestamp and are stamped at read time.
	Timestamp time.Time `json:"timestamp"`

	// Level is a severity label ("INFO", "EVENT").
	Level string `json:"level"`

	// Message is the log text (a serial line, or a lifecycle description).
	Message string `json:"message"`

	// Source identifies the origin ("serial" or "qmp").
	Source string `json:"source"`
}

// VMLogOptions controls a VM log stream.
type VMLogOptions struct {
	// Follow keeps the stream open, emitting new entries as they arrive, until
	// the context is canceled.
	Follow bool

	// TailLines, when > 0, limits the initial backlog to the last N lines of
	// the serial transcript.
	TailLines int

	// Since, when non-zero, drops backlog entries older than the given time.
	// Serial lines are stamped at read time, so Since is only meaningful for
	// entries observed during a follow.
	Since time.Time
}

// VMLogSink receives streamed log entries. Returning a non-nil error stops the
// stream (used by the gRPC handler to propagate a send failure or a client
// disconnect).
type VMLogSink func(LogEntry) error

// VMLogStreamer is the capability interface for streaming a VM's serial
// transcript and QMP lifecycle events.
type VMLogStreamer interface {
	// StreamVMLogs delivers backlog and (when opts.Follow is set) live log
	// entries to sink until the context is canceled, the transcript is
	// exhausted, or sink returns an error.
	StreamVMLogs(ctx context.Context, instanceID string, opts VMLogOptions, sink VMLogSink) error
}

// VMConsoleSession is a single attached viewer of a multiplexed VM console.
// Multiple sessions may be attached to the same VM concurrently; each receives
// every byte of console output from attach time, and any session may write
// input, which is serialized onto the single QEMU console connection.
type VMConsoleSession interface {
	// Output returns the channel of console output chunks for this viewer. The
	// channel is closed when the session is closed or the console ends.
	Output() <-chan []byte

	// Write sends input bytes to the VM console.
	Write(p []byte) error

	// Close detaches this viewer. It is safe to call more than once.
	Close() error
}

// VMConsole is the capability interface for interactive VM console access with
// multi-viewer fan-out.
type VMConsole interface {
	// AttachConsole attaches a new viewer to the VM console broker, creating
	// the broker (and its single upstream QEMU connection) on first use. The
	// returned session must be closed by the caller when done.
	AttachConsole(ctx context.Context, instanceID string) (VMConsoleSession, error)

	// SendConsoleInput writes input bytes to the VM console without attaching a
	// viewer. Input is serialized onto the same broker connection used by
	// attached viewers.
	SendConsoleInput(ctx context.Context, instanceID string, data []byte) error
}

// DiskAttachRequest describes a disk to hot-plug onto a running VM.
type DiskAttachRequest struct {
	// ID is the caller-facing disk identifier. When empty the manager
	// generates one.
	ID string

	// Path is the backing image path. When the file does not exist and SizeGB
	// is set, a qcow2 image of that size is created.
	Path string

	// Bus is the guest bus to attach to. Only "virtio" is supported for
	// hotplug; empty defaults to "virtio".
	Bus string

	// SizeGB is the size for a newly created image, in gibibytes.
	SizeGB uint64

	// Readonly attaches the disk read-only.
	Readonly bool
}

// VMDiskManager is the capability interface for runtime VM disk management. It
// performs online (QMP) hotplug/unplug on running VMs and online-or-offline
// resize depending on the VM's lifecycle state.
type VMDiskManager interface {
	// AttachDisk hot-plugs a virtio-blk disk onto a running VM (QMP
	// blockdev-add + device_add) and records it in the instance's disk list.
	AttachDisk(ctx context.Context, instanceID string, req DiskAttachRequest) (*DiskInfo, error)

	// DetachDisk unplugs a previously attached disk from a running VM (QMP
	// device_del + blockdev-del).
	DetachDisk(ctx context.Context, instanceID, diskID string) error

	// ResizeDisk changes a disk's virtual size. When the VM is running the
	// resize is online (QMP block_resize); when stopped it is offline
	// (qemu-img resize).
	ResizeDisk(ctx context.Context, instanceID, diskID string, newSizeGB uint64) error
}

// Compile-time proof that QEMUOrchestrator provides every VM operational
// capability.
var (
	_ VMMetricsReader = (*QEMUOrchestrator)(nil)
	_ VMLogStreamer   = (*QEMUOrchestrator)(nil)
	_ VMConsole       = (*QEMUOrchestrator)(nil)
	_ VMDiskManager   = (*QEMUOrchestrator)(nil)
)

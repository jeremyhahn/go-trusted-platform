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

package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// =============================================================================
// Operational VM REST handlers (metrics, disk hotplug/unplug/resize, logs
// snapshot, migrate)
// =============================================================================
//
// These handlers surface the platform.v1 ComputeService operational VM verbs
// over REST at feature parity with gRPC/QUIC/MCP. They type-assert the
// configured VM orchestrator on the canonical compute capability interfaces
// (VMMetricsReader / VMDiskManager / VMLogStreamer / VMMigrator) so a
// partially-capable orchestrator answers 501 for unsupported verbs rather than
// returning a silent stub.
//
// Interactive VM console (AttachVMConsole / SendVMConsoleInput) and log-FOLLOW
// are streaming-only and out of scope for the unary REST surface (SSE would be
// the vehicle); GET .../logs returns a bounded, non-following snapshot instead.

// VMMetricsResponse is the REST view of a VM metrics sample.
type VMMetricsResponse struct {
	VMID              string    `json:"vm_id"`
	CPUUsagePercent   float64   `json:"cpu_usage_percent"`
	MemoryUsedMB      uint64    `json:"memory_used_mb"`
	MemoryAvailableMB uint64    `json:"memory_available_mb"`
	DiskReadBytes     uint64    `json:"disk_read_bytes"`
	DiskWriteBytes    uint64    `json:"disk_write_bytes"`
	NetworkRxBytes    uint64    `json:"network_rx_bytes"`
	NetworkTxBytes    uint64    `json:"network_tx_bytes"`
	UptimeSeconds     uint32    `json:"uptime_seconds"`
	Timestamp         time.Time `json:"timestamp"`
}

// AttachVMDiskRequest is the POST body for hot-plugging a VM disk.
type AttachVMDiskRequest struct {
	DiskID   string `json:"disk_id,omitempty"`
	Path     string `json:"path"`
	Bus      string `json:"bus,omitempty"`
	SizeGB   uint64 `json:"size_gb,omitempty"`
	Readonly bool   `json:"readonly,omitempty"`
}

// AttachVMDiskResponse describes a freshly hot-plugged disk.
type AttachVMDiskResponse struct {
	VMID     string `json:"vm_id"`
	DiskID   string `json:"disk_id"`
	Path     string `json:"path"`
	Bus      string `json:"bus"`
	Index    int    `json:"index"`
	SizeGB   uint64 `json:"size_gb"`
	NodeName string `json:"node_name,omitempty"`
	Readonly bool   `json:"readonly"`
}

// ResizeVMDiskRequest is the PATCH body for resizing a VM disk.
type ResizeVMDiskRequest struct {
	NewSizeGB uint64 `json:"new_size_gb"`
}

// VMLogEntry is the REST view of a single VM log entry.
type VMLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
}

// VMLogsResponse is a bounded, non-following snapshot of a VM's logs.
type VMLogsResponse struct {
	VMID    string       `json:"vm_id"`
	Entries []VMLogEntry `json:"entries"`
	Count   int          `json:"count"`
}

// MigrateVMRequest is the POST body for migrating a VM.
type MigrateVMRequest struct {
	DestinationHost    string `json:"destination_host"`
	Live               bool   `json:"live,omitempty"`
	BandwidthLimitMbps uint64 `json:"bandwidth_limit_mbps,omitempty"`
}

// MigrateVMResponse reports a migration outcome.
type MigrateVMResponse struct {
	VMID            string `json:"vm_id"`
	DestinationHost string `json:"destination_host"`
	Mode            string `json:"mode"`
	Success         bool   `json:"success"`
	Message         string `json:"message"`
}

// ErrVMCapabilityUnsupported is returned when the configured VM orchestrator
// does not implement a requested operational capability.
type ErrVMCapabilityUnsupported struct {
	Capability string
}

// Error implements the error interface.
func (e ErrVMCapabilityUnsupported) Error() string {
	return "VM orchestrator does not support " + e.Capability
}

// handleGetVMMetrics handles GET /api/v1/compute/vms/{id}/metrics.
func (h *ComputeHandlers) handleGetVMMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}
	vmID := mux.Vars(r)["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}
	reader, ok := h.vmOrchestrator.(compute.VMMetricsReader)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrVMCapabilityUnsupported{Capability: "metrics"})
		return
	}
	m, err := reader.GetVMMetrics(ctx, vmID)
	if err != nil {
		h.writeVMError(w, "metrics", err)
		return
	}
	h.writeJSON(w, http.StatusOK, VMMetricsResponse{
		VMID:              vmID,
		CPUUsagePercent:   m.CPUUsagePercent,
		MemoryUsedMB:      m.MemoryUsedMB,
		MemoryAvailableMB: m.MemoryAvailableMB,
		DiskReadBytes:     m.DiskReadBytes,
		DiskWriteBytes:    m.DiskWriteBytes,
		NetworkRxBytes:    m.NetworkRxBytes,
		NetworkTxBytes:    m.NetworkTxBytes,
		UptimeSeconds:     m.UptimeSeconds,
		Timestamp:         time.Now().UTC(),
	})
}

// handleAttachVMDisk handles POST /api/v1/compute/vms/{id}/disks.
func (h *ComputeHandlers) handleAttachVMDisk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}
	vmID := mux.Vars(r)["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}
	var req AttachVMDiskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.Path == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "path"})
		return
	}
	mgr, ok := h.vmOrchestrator.(compute.VMDiskManager)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrVMCapabilityUnsupported{Capability: "disk management"})
		return
	}
	info, err := mgr.AttachDisk(ctx, vmID, compute.DiskAttachRequest{
		ID:       req.DiskID,
		Path:     req.Path,
		Bus:      req.Bus,
		SizeGB:   req.SizeGB,
		Readonly: req.Readonly,
	})
	if err != nil {
		h.writeVMError(w, "attach_disk", err)
		return
	}
	h.writeJSON(w, http.StatusCreated, AttachVMDiskResponse{
		VMID:     vmID,
		DiskID:   info.ID,
		Path:     info.Path,
		Bus:      info.Bus,
		Index:    info.Index,
		SizeGB:   info.SizeGB,
		NodeName: info.NodeName,
		Readonly: info.Readonly,
	})
}

// handleDetachVMDisk handles DELETE /api/v1/compute/vms/{id}/disks/{diskID}.
func (h *ComputeHandlers) handleDetachVMDisk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}
	vars := mux.Vars(r)
	vmID, diskID := vars["id"], vars["diskID"]
	if vmID == "" || diskID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id/diskID"})
		return
	}
	mgr, ok := h.vmOrchestrator.(compute.VMDiskManager)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrVMCapabilityUnsupported{Capability: "disk management"})
		return
	}
	if err := mgr.DetachDisk(ctx, vmID, diskID); err != nil {
		h.writeVMError(w, "detach_disk", err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "vm_id": vmID, "disk_id": diskID})
}

// handleResizeVMDisk handles PATCH /api/v1/compute/vms/{id}/disks/{diskID}.
func (h *ComputeHandlers) handleResizeVMDisk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}
	vars := mux.Vars(r)
	vmID, diskID := vars["id"], vars["diskID"]
	if vmID == "" || diskID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id/diskID"})
		return
	}
	var req ResizeVMDiskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.NewSizeGB == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "new_size_gb"})
		return
	}
	mgr, ok := h.vmOrchestrator.(compute.VMDiskManager)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrVMCapabilityUnsupported{Capability: "disk management"})
		return
	}
	if err := mgr.ResizeDisk(ctx, vmID, diskID, req.NewSizeGB); err != nil {
		h.writeVMError(w, "resize_disk", err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "vm_id": vmID, "disk_id": diskID, "new_size_gb": req.NewSizeGB})
}

// handleGetVMLogs handles GET /api/v1/compute/vms/{id}/logs. It returns a
// bounded, non-following snapshot; live follow is served over gRPC streaming.
func (h *ComputeHandlers) handleGetVMLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}
	vmID := mux.Vars(r)["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}
	tail := 100
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			tail = n
		}
	}
	streamer, ok := h.vmOrchestrator.(compute.VMLogStreamer)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrVMCapabilityUnsupported{Capability: "logs"})
		return
	}
	entries := make([]VMLogEntry, 0, 64)
	sink := func(e compute.LogEntry) error {
		entries = append(entries, VMLogEntry{Timestamp: e.Timestamp, Level: e.Level, Message: e.Message, Source: e.Source})
		return nil
	}
	if err := streamer.StreamVMLogs(ctx, vmID, compute.VMLogOptions{Follow: false, TailLines: tail}, sink); err != nil {
		h.writeVMError(w, "logs", err)
		return
	}
	h.writeJSON(w, http.StatusOK, VMLogsResponse{VMID: vmID, Entries: entries, Count: len(entries)})
}

// handleMigrateVM handles POST /api/v1/compute/vms/{id}/migrate.
func (h *ComputeHandlers) handleMigrateVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}
	vmID := mux.Vars(r)["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}
	var req MigrateVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.DestinationHost == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "destination_host"})
		return
	}
	migrator, ok := h.vmOrchestrator.(compute.VMMigrator)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrVMCapabilityUnsupported{Capability: "migration"})
		return
	}
	result, err := migrator.MigrateVM(ctx, vmID, req.DestinationHost, compute.MigrateOptions{
		Live:               req.Live,
		BandwidthLimitMbps: req.BandwidthLimitMbps,
	})
	if err != nil {
		h.writeVMMigrateError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, MigrateVMResponse{
		VMID:            vmID,
		DestinationHost: req.DestinationHost,
		Mode:            string(result.Mode),
		Success:         result.Success,
		Message:         result.Message,
	})
}

// writeVMMigrateError maps migration-specific sentinels to HTTP status codes,
// falling back to the shared VM error mapper for lifecycle errors.
func (h *ComputeHandlers) writeVMMigrateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, compute.ErrLiveMigrationRequiresSharedStorage),
		errors.Is(err, compute.ErrMigrationNotConfigured),
		errors.Is(err, compute.ErrMigrationTLSNotConfigured):
		h.writeError(w, http.StatusConflict, err)
	case errors.Is(err, compute.ErrMigrationDestinationRequired):
		h.writeError(w, http.StatusBadRequest, err)
	default:
		h.writeVMError(w, "migrate", err)
	}
}

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
)

// ContainerOpsOrchestrator is the orchestrator capability required for the
// operational container routes (exec, metrics, attach). The consolidated
// container.ComputeOrchestrator implements it; a QEMU/VM orchestrator does not.
type ContainerOpsOrchestrator interface {
	// Exec executes a command inside a running container.
	Exec(ctx context.Context, id string, opts container.ExecOptions) (*container.ExecResult, error)

	// Metrics reads a resource-usage snapshot for a running container.
	Metrics(ctx context.Context, id string) (*container.ContainerStats, error)

	// Attach starts an interactive attach session against a running container.
	Attach(ctx context.Context, id string, opts container.ExecOptions) (container.AttachSession, error)
}

// ExecContainerRESTRequest is the JSON body for POST /containers/{id}/exec.
type ExecContainerRESTRequest struct {
	Command    []string          `json:"command"`
	Env        map[string]string `json:"env,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	TTY        bool              `json:"tty,omitempty"`
}

// ExecContainerRESTResponse is the JSON response for a container exec.
type ExecContainerRESTResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// ContainerMetricsRESTResponse is the JSON response for container metrics.
type ContainerMetricsRESTResponse struct {
	CPUUsagePercent  float64 `json:"cpu_usage_percent"`
	MemoryUsedBytes  uint64  `json:"memory_used_bytes"`
	MemoryLimitBytes uint64  `json:"memory_limit_bytes"`
	DiskReadBytes    uint64  `json:"disk_read_bytes"`
	DiskWriteBytes   uint64  `json:"disk_write_bytes"`
	NetworkRxBytes   uint64  `json:"network_rx_bytes"`
	NetworkTxBytes   uint64  `json:"network_tx_bytes"`
	UptimeSeconds    uint64  `json:"uptime_seconds"`
}

// RegisterOpsRoutes registers the operational container routes (exec, metrics,
// attach) on the provided router. It is invoked from RegisterRoutes.
func (h *ContainerHandlers) RegisterOpsRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/containers/{id}/exec", h.handleExecContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/containers/{id}/metrics", h.handleContainerMetrics).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/containers/{id}/attach", h.handleAttachContainer).Methods(http.MethodGet)
}

// handleExecContainer handles POST /api/v1/containers/{id}/exec.
func (h *ContainerHandlers) handleExecContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	opsOrch, ok := h.orchestrator.(ContainerOpsOrchestrator)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrContainerOperationFailed{
			Operation: "exec",
			Cause:     errors.New("exec not supported by this orchestrator"),
		})
		return
	}

	var req ExecContainerRESTRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}
	if len(req.Command) == 0 {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "command is required"})
		return
	}

	opts := container.ExecOptions{
		Command:    req.Command,
		WorkingDir: req.WorkingDir,
		TTY:        req.TTY,
	}
	for k, v := range req.Env {
		opts.Env = append(opts.Env, k+"="+v)
	}

	result, err := opsOrch.Exec(ctx, containerID, opts)
	if err != nil {
		h.logger.Error("Failed to exec in container", "error", err, "id", containerID)
		h.writeContainerError(w, "exec", err)
		return
	}

	h.writeJSON(w, http.StatusOK, ExecContainerRESTResponse{
		ExitCode: result.ExitCode,
		Stdout:   string(result.Stdout),
		Stderr:   string(result.Stderr),
	})
}

// handleContainerMetrics handles GET /api/v1/containers/{id}/metrics.
func (h *ContainerHandlers) handleContainerMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	opsOrch, ok := h.orchestrator.(ContainerOpsOrchestrator)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrContainerOperationFailed{
			Operation: "metrics",
			Cause:     errors.New("metrics not supported by this orchestrator"),
		})
		return
	}

	stats, err := opsOrch.Metrics(ctx, containerID)
	if err != nil {
		h.logger.Error("Failed to read container metrics", "error", err, "id", containerID)
		h.writeContainerError(w, "metrics", err)
		return
	}

	h.writeJSON(w, http.StatusOK, ContainerMetricsRESTResponse{
		CPUUsagePercent:  stats.CPUUsagePercent,
		MemoryUsedBytes:  stats.MemoryUsedBytes,
		MemoryLimitBytes: stats.MemoryLimitBytes,
		DiskReadBytes:    stats.DiskReadBytes,
		DiskWriteBytes:   stats.DiskWriteBytes,
		NetworkRxBytes:   stats.NetworkRxBytes,
		NetworkTxBytes:   stats.NetworkTxBytes,
		UptimeSeconds:    stats.UptimeSeconds,
	})
}

// handleAttachContainer handles GET /api/v1/containers/{id}/attach. The console
// output is streamed as Server-Sent Events. This route is output-only:
// interactive stdin injection requires a bidirectional transport (the gRPC
// AttachContainer server stream is the canonical interactive surface).
func (h *ContainerHandlers) handleAttachContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	opsOrch, ok := h.orchestrator.(ContainerOpsOrchestrator)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrContainerOperationFailed{
			Operation: "attach",
			Cause:     errors.New("attach not supported by this orchestrator"),
		})
		return
	}

	session, err := opsOrch.Attach(ctx, containerID, container.ExecOptions{})
	if err != nil {
		h.logger.Error("Failed to attach to container", "error", err, "id", containerID)
		h.writeContainerError(w, "attach", err)
		return
	}
	defer session.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, ErrContainerOperationFailed{
			Operation: "attach",
			Cause:     errors.New("streaming not supported"),
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	output := session.Output()
	for {
		select {
		case <-ctx.Done():
			return
		case chunk, ok := <-output:
			if !ok {
				fmt.Fprintf(w, "event: end\ndata: session ended\n\n")
				flusher.Flush()
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", string(chunk.Data))
			flusher.Flush()
		}
	}
}

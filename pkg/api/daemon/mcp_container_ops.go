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

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
)

// ErrContainerExecNotSupported is returned when container exec is not supported
// by the active orchestrator.
type ErrContainerExecNotSupported struct{}

func (e ErrContainerExecNotSupported) Error() string {
	return "container exec not supported via orchestrator"
}

// ErrContainerMetricsNotSupported is returned when container metrics are not
// supported by the active orchestrator.
type ErrContainerMetricsNotSupported struct{}

func (e ErrContainerMetricsNotSupported) Error() string {
	return "container metrics not supported via orchestrator"
}

// ContainerExec executes a command inside a running container and returns the
// buffered result. It delegates to the orchestrator's Exec verb — the same
// service logic the gRPC ExecContainer RPC and REST exec route use. The MCP
// tool response model returns the captured stdout/stderr as text and the
// process exit code.
func (m *MCPServiceProvider) ContainerExec(ctx context.Context, id string, command []string, env map[string]string, workingDir string, tty bool) (interface{}, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrContainerServiceNotAvailable{}
	}
	if id == "" {
		return nil, ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}
	if len(command) == 0 {
		return nil, ErrContainerInvalidParameter{Parameter: "command", Reason: "command is required"}
	}

	executor, ok := m.computeOrchestrator.(containerExecutor)
	if !ok {
		return nil, ErrContainerExecNotSupported{}
	}

	opts := container.ExecOptions{
		Command:    command,
		WorkingDir: workingDir,
		TTY:        tty,
	}
	for k, v := range env {
		opts.Env = append(opts.Env, k+"="+v)
	}

	result, err := executor.Exec(ctx, id, opts)
	if err != nil {
		m.logger.Error("failed to exec in container", "container_id", id, "error", err)
		return nil, classifyComputeErr(ErrContainerOperationFailed{Operation: "exec", Cause: err}, containerOpsErrToStatus)
	}

	return map[string]interface{}{
		"exit_code": result.ExitCode,
		"stdout":    string(result.Stdout),
		"stderr":    string(result.Stderr),
	}, nil
}

// ContainerMetrics reads a resource-usage snapshot for a running container. It
// delegates to the orchestrator's Metrics verb — the same service logic the
// gRPC GetContainerMetrics RPC and REST metrics route use.
func (m *MCPServiceProvider) ContainerMetrics(ctx context.Context, id string) (interface{}, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrContainerServiceNotAvailable{}
	}
	if id == "" {
		return nil, ErrContainerInvalidParameter{Parameter: "id", Reason: "container ID is required"}
	}

	reader, ok := m.computeOrchestrator.(containerMetricsReader)
	if !ok {
		return nil, ErrContainerMetricsNotSupported{}
	}

	stats, err := reader.Metrics(ctx, id)
	if err != nil {
		m.logger.Error("failed to read container metrics", "container_id", id, "error", err)
		return nil, classifyComputeErr(ErrContainerOperationFailed{Operation: "metrics", Cause: err}, containerOpsErrToStatus)
	}

	return map[string]interface{}{
		"cpu_usage_percent":  stats.CPUUsagePercent,
		"memory_used_bytes":  stats.MemoryUsedBytes,
		"memory_limit_bytes": stats.MemoryLimitBytes,
		"disk_read_bytes":    stats.DiskReadBytes,
		"disk_write_bytes":   stats.DiskWriteBytes,
		"network_rx_bytes":   stats.NetworkRxBytes,
		"network_tx_bytes":   stats.NetworkTxBytes,
		"uptime_seconds":     stats.UptimeSeconds,
	}, nil
}

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
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Container operational capability interfaces. The consolidated
// container.ComputeOrchestrator implements all three; a QEMU/VM orchestrator
// does not. Transports type-assert the compute.Orchestrator against these and
// return a typed not-supported error when the assertion fails, so the base
// compute.Orchestrator interface stays minimal.

// containerExecutor is the orchestrator capability required to execute a
// command inside a running container.
type containerExecutor interface {
	Exec(ctx context.Context, id string, opts container.ExecOptions) (*container.ExecResult, error)
}

// containerMetricsReader is the orchestrator capability required to read a
// container's resource metrics.
type containerMetricsReader interface {
	Metrics(ctx context.Context, id string) (*container.ContainerStats, error)
}

// containerAttacher is the orchestrator capability required to attach an
// interactive session to a running container.
type containerAttacher interface {
	Attach(ctx context.Context, id string, opts container.ExecOptions) (container.AttachSession, error)
}

// execOptionsFromProto builds container exec options from a pb request,
// flattening the structured EnvVar list into KEY=VALUE strings.
func execOptionsFromProto(req *platformv1.ExecContainerRequest) container.ExecOptions {
	opts := container.ExecOptions{
		Command:    req.GetCommand(),
		WorkingDir: req.GetWorkingDir(),
		TTY:        req.GetTty(),
	}
	for _, env := range req.GetEnv() {
		if env == nil || env.GetName() == "" {
			continue
		}
		opts.Env = append(opts.Env, env.GetName()+"="+env.GetValue())
	}
	return opts
}

// execResultToProto maps a container exec result onto the pb response.
func execResultToProto(result *container.ExecResult) *platformv1.ExecContainerResponse {
	return &platformv1.ExecContainerResponse{
		Status: &platformv1.Status{
			Success: result.ExitCode == 0,
			Message: "container exec completed",
		},
		ExitCode: int32(result.ExitCode),
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	}
}

// containerStatsToProto maps a container resource snapshot onto the pb metrics
// message. Byte counts are converted to megabytes for the memory fields to
// match the pb contract.
func containerStatsToProto(stats *container.ContainerStats) *platformv1.ContainerMetrics {
	const bytesPerMB = 1024 * 1024
	return &platformv1.ContainerMetrics{
		CpuUsagePercent: stats.CPUUsagePercent,
		MemoryUsedMb:    stats.MemoryUsedBytes / bytesPerMB,
		MemoryLimitMb:   stats.MemoryLimitBytes / bytesPerMB,
		DiskReadBytes:   stats.DiskReadBytes,
		DiskWriteBytes:  stats.DiskWriteBytes,
		NetworkRxBytes:  stats.NetworkRxBytes,
		NetworkTxBytes:  stats.NetworkTxBytes,
		UptimeSeconds:   uint32(stats.UptimeSeconds),
	}
}

// attachChunkToProto maps a console chunk onto a pb ConsoleOutput message.
func attachChunkToProto(chunk container.AttachChunk) *platformv1.ConsoleOutput {
	return &platformv1.ConsoleOutput{
		Data:      chunk.Data,
		Stream:    chunk.Stream,
		Timestamp: timestamppb.Now(),
	}
}

// containerOpsErrToStatus maps container operational-verb errors onto gRPC
// status codes. It extends the log-error mapping with the exec/metrics/attach
// capability sentinels.
func containerOpsErrToStatus(err error) error {
	switch {
	case errors.Is(err, container.ErrExecNotSupported),
		errors.Is(err, container.ErrMetricsNotSupported),
		errors.Is(err, container.ErrAttachNotSupported):
		return status.Error(codes.Unimplemented, err.Error())
	case errors.Is(err, container.ErrExecCommandRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, container.ErrContainerNotFound),
		errors.Is(err, compute.ErrInstanceNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, container.ErrInvalidContainerID),
		errors.Is(err, compute.ErrInvalidInstanceID):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

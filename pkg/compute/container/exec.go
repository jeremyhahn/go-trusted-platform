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

package container

import (
	"context"
	"errors"
)

// Operational-capability sentinel errors for the exec, metrics, and attach
// verbs. They are matched with errors.Is by the transport layers to select
// the appropriate status code.
var (
	// ErrExecCommandRequired is returned when an exec request omits its command.
	ErrExecCommandRequired = errors.New("exec command is required")

	// ErrExecNotSupported is returned when the backend cannot execute commands
	// inside containers.
	ErrExecNotSupported = errors.New("container exec not supported by backend")

	// ErrMetricsNotSupported is returned when the backend cannot report
	// container metrics.
	ErrMetricsNotSupported = errors.New("container metrics not supported by backend")

	// ErrAttachNotSupported is returned when the backend cannot attach an
	// interactive session to a container.
	ErrAttachNotSupported = errors.New("container attach not supported by backend")
)

// ExecOptions configures a command executed inside a running container.
type ExecOptions struct {
	// Command is the argv executed inside the container (argv[0] is the binary).
	Command []string

	// Env is a list of KEY=VALUE strings added to the exec environment.
	Env []string

	// WorkingDir is the working directory for the executed process.
	WorkingDir string

	// TTY allocates a pseudo-terminal for the process. On a buffered Exec the
	// combined output is returned on the result's Stdout.
	TTY bool
}

// ExecResult holds the buffered result of a non-interactive container exec.
type ExecResult struct {
	// ExitCode is the exit status of the executed process.
	ExitCode int

	// Stdout is the captured standard output (combined output for a TTY exec).
	Stdout []byte

	// Stderr is the captured standard error (empty for a TTY exec).
	Stderr []byte
}

// ContainerStats is a point-in-time resource-usage snapshot for a container.
type ContainerStats struct {
	// CPUUsagePercent is the CPU utilisation over the sampling window.
	CPUUsagePercent float64

	// MemoryUsedBytes is the current memory charge.
	MemoryUsedBytes uint64

	// MemoryLimitBytes is the memory hard limit; 0 means unlimited.
	MemoryLimitBytes uint64

	// DiskReadBytes is the total bytes read across block devices.
	DiskReadBytes uint64

	// DiskWriteBytes is the total bytes written across block devices.
	DiskWriteBytes uint64

	// NetworkRxBytes is the total bytes received across non-loopback interfaces.
	NetworkRxBytes uint64

	// NetworkTxBytes is the total bytes transmitted across non-loopback interfaces.
	NetworkTxBytes uint64

	// UptimeSeconds is the container's uptime since it was started.
	UptimeSeconds uint64
}

// AttachChunk is one framed slice of container console output.
type AttachChunk struct {
	// Stream identifies the origin: "console", "stdout", or "stderr".
	Stream string

	// Data is the raw output bytes.
	Data []byte
}

// AttachSession is an interactive attach broker over a container console.
// Output delivers console chunks until the session ends and the channel is
// closed; Wait blocks for the exit code; Close tears the session down.
type AttachSession interface {
	Output() <-chan AttachChunk
	Wait() (int, error)
	Close() error
}

// execBackend is the PodmanBackend capability required to execute commands
// inside a container. The EmbeddedPodmanAdapter satisfies it; the engine
// type-asserts against it so the base PodmanBackend interface stays minimal.
type execBackend interface {
	ExecContainer(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error)
}

// metricsBackend is the PodmanBackend capability required to read container
// resource metrics.
type metricsBackend interface {
	ContainerResourceStats(ctx context.Context, id string) (*ContainerStats, error)
}

// attachBackend is the PodmanBackend capability required to attach an
// interactive session to a container.
type attachBackend interface {
	AttachContainer(ctx context.Context, id string, opts ExecOptions) (AttachSession, error)
}

// Exec executes a command inside a running container and returns its buffered
// output and exit code. It delegates to the backend's OCI-runtime exec.
func (o *Orchestrator) Exec(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}
	if id == "" {
		return nil, ErrInvalidContainerID
	}
	if len(opts.Command) == 0 {
		return nil, ErrExecCommandRequired
	}

	c, err := o.getContainer(id)
	if err != nil {
		return nil, err
	}

	backend, ok := o.podman.(execBackend)
	if !ok {
		return nil, ErrExecNotSupported
	}

	result, err := backend.ExecContainer(ctx, id, opts)
	if err != nil {
		return nil, NewContainerError(id, c.Name, "exec", err)
	}
	return result, nil
}

// Metrics reads a resource-usage snapshot for a running container from its
// cgroup controllers and network namespace.
func (o *Orchestrator) Metrics(ctx context.Context, id string) (*ContainerStats, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}
	if id == "" {
		return nil, ErrInvalidContainerID
	}

	c, err := o.getContainer(id)
	if err != nil {
		return nil, err
	}

	backend, ok := o.podman.(metricsBackend)
	if !ok {
		return nil, ErrMetricsNotSupported
	}

	stats, err := backend.ContainerResourceStats(ctx, id)
	if err != nil {
		return nil, NewContainerError(id, c.Name, "metrics", err)
	}
	return stats, nil
}

// Attach starts an interactive attach session against a running container.
func (o *Orchestrator) Attach(ctx context.Context, id string, opts ExecOptions) (AttachSession, error) {
	if o.closed.Load() {
		return nil, ErrOrchestratorClosed
	}
	if id == "" {
		return nil, ErrInvalidContainerID
	}

	c, err := o.getContainer(id)
	if err != nil {
		return nil, err
	}

	backend, ok := o.podman.(attachBackend)
	if !ok {
		return nil, ErrAttachNotSupported
	}

	session, err := backend.AttachContainer(ctx, id, opts)
	if err != nil {
		return nil, NewContainerError(id, c.Name, "attach", err)
	}
	return session, nil
}

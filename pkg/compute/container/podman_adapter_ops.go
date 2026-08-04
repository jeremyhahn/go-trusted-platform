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
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
)

// Compile-time assertions that the embedded adapter bridges the operational
// backend capabilities the engine type-asserts against.
var (
	_ execBackend    = (*EmbeddedPodmanAdapter)(nil)
	_ metricsBackend = (*EmbeddedPodmanAdapter)(nil)
	_ attachBackend  = (*EmbeddedPodmanAdapter)(nil)
)

// ExecContainer executes a command inside a running container by delegating to
// the embedded manager's OCI-runtime exec, converting the option and result
// types across the package boundary.
func (a *EmbeddedPodmanAdapter) ExecContainer(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error) {
	executor, ok := a.manager.(podman.Executor)
	if !ok {
		return nil, ErrExecNotSupported
	}

	result, err := executor.ExecContainer(ctx, id, podman.ExecOptions{
		Command:    opts.Command,
		Env:        opts.Env,
		WorkingDir: opts.WorkingDir,
		TTY:        opts.TTY,
	})
	if err != nil {
		return nil, err
	}

	return &ExecResult{
		ExitCode: result.ExitCode,
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	}, nil
}

// ContainerResourceStats reads a resource-usage snapshot for a container by
// delegating to the embedded manager's cgroup-backed metrics reader.
func (a *EmbeddedPodmanAdapter) ContainerResourceStats(ctx context.Context, id string) (*ContainerStats, error) {
	reader, ok := a.manager.(podman.MetricsReader)
	if !ok {
		return nil, ErrMetricsNotSupported
	}

	stats, err := reader.ResourceStats(ctx, id)
	if err != nil {
		return nil, err
	}

	return &ContainerStats{
		CPUUsagePercent:  stats.CPUUsagePercent,
		MemoryUsedBytes:  stats.MemoryUsedBytes,
		MemoryLimitBytes: stats.MemoryLimitBytes,
		DiskReadBytes:    stats.DiskReadBytes,
		DiskWriteBytes:   stats.DiskWriteBytes,
		NetworkRxBytes:   stats.NetworkRxBytes,
		NetworkTxBytes:   stats.NetworkTxBytes,
		UptimeSeconds:    stats.UptimeSeconds,
	}, nil
}

// AttachContainer starts an interactive attach session, wrapping the manager's
// pseudo-terminal session so the console chunks are delivered on the container
// package's own channel type.
func (a *EmbeddedPodmanAdapter) AttachContainer(ctx context.Context, id string, opts ExecOptions) (AttachSession, error) {
	attacher, ok := a.manager.(podman.Attacher)
	if !ok {
		return nil, ErrAttachNotSupported
	}

	session, err := attacher.AttachContainer(ctx, id, podman.ExecOptions{
		Command:    opts.Command,
		Env:        opts.Env,
		WorkingDir: opts.WorkingDir,
		TTY:        opts.TTY,
	})
	if err != nil {
		return nil, err
	}

	return &podmanAttachSession{inner: session, done: make(chan struct{})}, nil
}

// podmanAttachSession adapts a podman.AttachSession to the container package's
// AttachSession, converting the console chunk type over a forwarding goroutine
// that is torn down when the session is closed.
type podmanAttachSession struct {
	inner podman.AttachSession
	out   chan AttachChunk
	done  chan struct{}

	startOnce sync.Once
	closeOnce sync.Once
}

// Output returns the console channel, starting the forwarding goroutine on
// first use.
func (s *podmanAttachSession) Output() <-chan AttachChunk {
	s.startOnce.Do(func() {
		s.out = make(chan AttachChunk, 16)
		go s.forward()
	})
	return s.out
}

// forward converts and relays chunks from the inner session onto the container
// channel until the inner channel closes or the session is closed.
func (s *podmanAttachSession) forward() {
	defer close(s.out)
	for chunk := range s.inner.Output() {
		select {
		case s.out <- AttachChunk{Stream: chunk.Stream, Data: chunk.Data}:
		case <-s.done:
			return
		}
	}
}

// Wait blocks until the attached process exits and returns its exit code.
func (s *podmanAttachSession) Wait() (int, error) {
	return s.inner.Wait()
}

// Close tears down the forwarding goroutine and the inner session. It is
// idempotent.
func (s *podmanAttachSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	return s.inner.Close()
}

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

package podman

import "context"

// Compile-time assertions that the embedded manager implements the operational
// capability interfaces.
var (
	_ Executor      = (*podmanManager)(nil)
	_ MetricsReader = (*podmanManager)(nil)
	_ Attacher      = (*podmanManager)(nil)
)

// ExecContainer executes a command inside a running container via the embedded
// OCI runtime and returns its buffered output and exit code.
func (m *podmanManager) ExecContainer(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}
	if id == "" {
		return nil, NewContainerError("", "exec", ErrContainerNotFound)
	}
	return m.runtime.Exec(ctx, id, opts)
}

// ResourceStats reads a resource-usage snapshot for a running container from
// its cgroup v2 controllers and network namespace.
func (m *podmanManager) ResourceStats(ctx context.Context, id string) (*ResourceStats, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}
	if id == "" {
		return nil, NewContainerError("", "metrics", ErrContainerNotFound)
	}
	return m.runtime.Stats(ctx, id)
}

// AttachContainer starts an interactive pseudo-terminal attach session against
// a running container.
func (m *podmanManager) AttachContainer(ctx context.Context, id string, opts ExecOptions) (AttachSession, error) {
	if !m.initialized.Load() {
		return nil, ErrClientNotConnected
	}
	if id == "" {
		return nil, NewContainerError("", "attach", ErrContainerNotFound)
	}
	return m.runtime.Attach(ctx, id, opts)
}

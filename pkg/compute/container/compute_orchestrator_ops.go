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

import "context"

// Operational capability verbs (Exec / Metrics / Attach) forwarded from the
// consolidated ComputeOrchestrator to the rich engine. They mirror the
// existing rich-verb forwarding (Logs / Attest) and let the daemon transports
// type-assert the compute.Orchestrator to reach these container capabilities.

// Exec executes a command inside a running container and returns its buffered
// output and exit code.
func (o *ComputeOrchestrator) Exec(ctx context.Context, instanceID string, opts ExecOptions) (*ExecResult, error) {
	if o.engine == nil {
		return nil, ErrOrchestratorClosed
	}
	return o.engine.Exec(ctx, instanceID, opts)
}

// Metrics reads a resource-usage snapshot for a running container.
func (o *ComputeOrchestrator) Metrics(ctx context.Context, instanceID string) (*ContainerStats, error) {
	if o.engine == nil {
		return nil, ErrOrchestratorClosed
	}
	return o.engine.Metrics(ctx, instanceID)
}

// Attach starts an interactive attach session against a running container.
func (o *ComputeOrchestrator) Attach(ctx context.Context, instanceID string, opts ExecOptions) (AttachSession, error) {
	if o.engine == nil {
		return nil, ErrOrchestratorClosed
	}
	return o.engine.Attach(ctx, instanceID, opts)
}

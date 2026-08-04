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
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOpsComputeOrchestrator builds a ComputeOrchestrator over an ops-capable
// engine and returns it along with a created container ID.
func newOpsComputeOrchestrator(t *testing.T, backend PodmanBackend) (*ComputeOrchestrator, string) {
	t.Helper()

	engine, err := NewOrchestrator(OrchestratorConfig{Logger: slog.Default()}, WithPodmanBackend(backend))
	require.NoError(t, err)

	c, err := engine.Create(context.Background(), &OrchestratorContainerSpec{Name: "ops-ce", Image: "alpine:latest"})
	require.NoError(t, err)

	orch, err := NewComputeOrchestrator(newTestComputeConfig(), logging.DefaultLogger(), WithComputeEngine(engine))
	require.NoError(t, err)
	return orch, c.ID
}

func TestComputeOrchestratorExec_Forwards(t *testing.T) {
	backend := &opsMockBackend{
		MockPodmanBackend: NewMockPodmanBackend(),
		execResult:        &ExecResult{ExitCode: 0, Stdout: []byte("forwarded")},
	}
	orch, id := newOpsComputeOrchestrator(t, backend)

	result, err := orch.Exec(context.Background(), id, ExecOptions{Command: []string{"echo", "x"}})
	require.NoError(t, err)
	assert.Equal(t, "forwarded", string(result.Stdout))
}

func TestComputeOrchestratorMetrics_Forwards(t *testing.T) {
	backend := &opsMockBackend{
		MockPodmanBackend: NewMockPodmanBackend(),
		stats:             &ContainerStats{CPUUsagePercent: 5.0, MemoryUsedBytes: 512},
	}
	orch, id := newOpsComputeOrchestrator(t, backend)

	stats, err := orch.Metrics(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 5.0, stats.CPUUsagePercent)
	assert.Equal(t, uint64(512), stats.MemoryUsedBytes)
}

func TestComputeOrchestratorAttach_Forwards(t *testing.T) {
	backend := &opsMockBackend{
		MockPodmanBackend: NewMockPodmanBackend(),
		session:           newStaticAttachSession([]AttachChunk{{Stream: "console", Data: []byte("z")}}, 0),
	}
	orch, id := newOpsComputeOrchestrator(t, backend)

	session, err := orch.Attach(context.Background(), id, ExecOptions{})
	require.NoError(t, err)
	chunk := <-session.Output()
	assert.Equal(t, "z", string(chunk.Data))
}

// compile-time proof that ComputeOrchestrator remains a compute.Orchestrator.
var _ compute.Orchestrator = (*ComputeOrchestrator)(nil)

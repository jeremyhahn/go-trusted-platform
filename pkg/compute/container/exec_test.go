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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// opsMockBackend extends the base mock with the exec/metrics/attach
// capabilities so the engine's type-assertions succeed.
type opsMockBackend struct {
	*MockPodmanBackend

	execResult *ExecResult
	execErr    error
	execOpts   ExecOptions

	stats    *ContainerStats
	statsErr error

	session   AttachSession
	attachErr error
}

func (m *opsMockBackend) ExecContainer(ctx context.Context, id string, opts ExecOptions) (*ExecResult, error) {
	m.execOpts = opts
	return m.execResult, m.execErr
}

func (m *opsMockBackend) ContainerResourceStats(ctx context.Context, id string) (*ContainerStats, error) {
	return m.stats, m.statsErr
}

func (m *opsMockBackend) AttachContainer(ctx context.Context, id string, opts ExecOptions) (AttachSession, error) {
	return m.session, m.attachErr
}

// staticAttachSession is an in-memory AttachSession for engine-level tests.
type staticAttachSession struct {
	out      chan AttachChunk
	exitCode int
	closed   bool
}

func newStaticAttachSession(chunks []AttachChunk, exitCode int) *staticAttachSession {
	out := make(chan AttachChunk, len(chunks))
	for _, c := range chunks {
		out <- c
	}
	close(out)
	return &staticAttachSession{out: out, exitCode: exitCode}
}

func (s *staticAttachSession) Output() <-chan AttachChunk { return s.out }
func (s *staticAttachSession) Wait() (int, error)         { return s.exitCode, nil }
func (s *staticAttachSession) Close() error               { s.closed = true; return nil }

func newOpsOrchestrator(t *testing.T, backend PodmanBackend) (*Orchestrator, *Container) {
	t.Helper()

	orch, err := NewOrchestrator(OrchestratorConfig{Logger: testLogger()}, WithPodmanBackend(backend))
	require.NoError(t, err)

	c, err := orch.Create(context.Background(), &OrchestratorContainerSpec{
		Name:  "ops-container",
		Image: "alpine:latest",
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	return orch, c
}

func TestOrchestratorExec_Success(t *testing.T) {
	backend := &opsMockBackend{
		MockPodmanBackend: NewMockPodmanBackend(),
		execResult:        &ExecResult{ExitCode: 0, Stdout: []byte("out"), Stderr: []byte("err")},
	}
	orch, c := newOpsOrchestrator(t, backend)
	defer orch.Close()

	result, err := orch.Exec(context.Background(), c.ID, ExecOptions{
		Command: []string{"echo", "hi"},
		Env:     []string{"K=V"},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, "out", string(result.Stdout))
	assert.Equal(t, "err", string(result.Stderr))
	assert.Equal(t, []string{"echo", "hi"}, backend.execOpts.Command)
}

func TestOrchestratorExec_EmptyCommand(t *testing.T) {
	backend := &opsMockBackend{MockPodmanBackend: NewMockPodmanBackend()}
	orch, c := newOpsOrchestrator(t, backend)
	defer orch.Close()

	_, err := orch.Exec(context.Background(), c.ID, ExecOptions{})
	require.ErrorIs(t, err, ErrExecCommandRequired)
}

func TestOrchestratorExec_MissingContainer(t *testing.T) {
	backend := &opsMockBackend{MockPodmanBackend: NewMockPodmanBackend()}
	orch, _ := newOpsOrchestrator(t, backend)
	defer orch.Close()

	_, err := orch.Exec(context.Background(), "ghost", ExecOptions{Command: []string{"ls"}})
	require.ErrorIs(t, err, ErrContainerNotFound)
}

func TestOrchestratorExec_BackendError(t *testing.T) {
	sentinel := errors.New("exec failed")
	backend := &opsMockBackend{MockPodmanBackend: NewMockPodmanBackend(), execErr: sentinel}
	orch, c := newOpsOrchestrator(t, backend)
	defer orch.Close()

	_, err := orch.Exec(context.Background(), c.ID, ExecOptions{Command: []string{"ls"}})
	require.ErrorIs(t, err, sentinel)
}

func TestOrchestratorExec_NotSupported(t *testing.T) {
	// The base mock does not implement the exec capability.
	orch, c := newOpsOrchestrator(t, NewMockPodmanBackend())
	defer orch.Close()

	_, err := orch.Exec(context.Background(), c.ID, ExecOptions{Command: []string{"ls"}})
	require.ErrorIs(t, err, ErrExecNotSupported)
}

func TestOrchestratorMetrics_Success(t *testing.T) {
	backend := &opsMockBackend{
		MockPodmanBackend: NewMockPodmanBackend(),
		stats: &ContainerStats{
			CPUUsagePercent:  12.5,
			MemoryUsedBytes:  1024,
			MemoryLimitBytes: 4096,
			NetworkRxBytes:   10,
			NetworkTxBytes:   20,
			UptimeSeconds:    30,
		},
	}
	orch, c := newOpsOrchestrator(t, backend)
	defer orch.Close()

	stats, err := orch.Metrics(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Equal(t, 12.5, stats.CPUUsagePercent)
	assert.Equal(t, uint64(1024), stats.MemoryUsedBytes)
	assert.Equal(t, uint64(30), stats.UptimeSeconds)
}

func TestOrchestratorMetrics_NotSupported(t *testing.T) {
	orch, c := newOpsOrchestrator(t, NewMockPodmanBackend())
	defer orch.Close()

	_, err := orch.Metrics(context.Background(), c.ID)
	require.ErrorIs(t, err, ErrMetricsNotSupported)
}

func TestOrchestratorMetrics_BackendError(t *testing.T) {
	sentinel := errors.New("cgroup read failed")
	backend := &opsMockBackend{MockPodmanBackend: NewMockPodmanBackend(), statsErr: sentinel}
	orch, c := newOpsOrchestrator(t, backend)
	defer orch.Close()

	_, err := orch.Metrics(context.Background(), c.ID)
	require.ErrorIs(t, err, sentinel)
}

func TestOrchestratorAttach_Success(t *testing.T) {
	backend := &opsMockBackend{
		MockPodmanBackend: NewMockPodmanBackend(),
		session: newStaticAttachSession([]AttachChunk{
			{Stream: "console", Data: []byte("a")},
			{Stream: "console", Data: []byte("b")},
		}, 0),
	}
	orch, c := newOpsOrchestrator(t, backend)
	defer orch.Close()

	session, err := orch.Attach(context.Background(), c.ID, ExecOptions{})
	require.NoError(t, err)

	var out []byte
	for chunk := range session.Output() {
		out = append(out, chunk.Data...)
	}
	assert.Equal(t, "ab", string(out))

	code, err := session.Wait()
	require.NoError(t, err)
	assert.Equal(t, 0, code)
}

func TestOrchestratorAttach_NotSupported(t *testing.T) {
	orch, c := newOpsOrchestrator(t, NewMockPodmanBackend())
	defer orch.Close()

	_, err := orch.Attach(context.Background(), c.ID, ExecOptions{})
	require.ErrorIs(t, err, ErrAttachNotSupported)
}

func TestOrchestratorOps_Closed(t *testing.T) {
	orch, c := newOpsOrchestrator(t, &opsMockBackend{MockPodmanBackend: NewMockPodmanBackend()})
	require.NoError(t, orch.Close())

	_, err := orch.Exec(context.Background(), c.ID, ExecOptions{Command: []string{"ls"}})
	assert.ErrorIs(t, err, ErrOrchestratorClosed)
	_, err = orch.Metrics(context.Background(), c.ID)
	assert.ErrorIs(t, err, ErrOrchestratorClosed)
	_, err = orch.Attach(context.Background(), c.ID, ExecOptions{})
	assert.ErrorIs(t, err, ErrOrchestratorClosed)
}

// -----------------------------------------------------------------------------
// EmbeddedPodmanAdapter conversion tests
// -----------------------------------------------------------------------------

// fakeOpsManager embeds the podman.PodmanManager interface (nil) and only
// implements the operational capability methods the adapter type-asserts.
type fakeOpsManager struct {
	podman.PodmanManager

	execResult *podman.ExecResult
	execErr    error
	stats      *podman.ResourceStats
	statsErr   error
	session    podman.AttachSession
	attachErr  error
}

func (f *fakeOpsManager) ExecContainer(ctx context.Context, id string, opts podman.ExecOptions) (*podman.ExecResult, error) {
	return f.execResult, f.execErr
}

func (f *fakeOpsManager) ResourceStats(ctx context.Context, id string) (*podman.ResourceStats, error) {
	return f.stats, f.statsErr
}

func (f *fakeOpsManager) AttachContainer(ctx context.Context, id string, opts podman.ExecOptions) (podman.AttachSession, error) {
	return f.session, f.attachErr
}

// bareManager implements no operational capability.
type bareManager struct {
	podman.PodmanManager
}

type fakePodmanSession struct {
	out chan podman.AttachChunk
}

func (s *fakePodmanSession) Output() <-chan podman.AttachChunk { return s.out }
func (s *fakePodmanSession) Wait() (int, error)                { return 0, nil }
func (s *fakePodmanSession) Close() error                      { return nil }

func TestAdapterExec_Conversion(t *testing.T) {
	mgr := &fakeOpsManager{execResult: &podman.ExecResult{ExitCode: 2, Stdout: []byte("x"), Stderr: []byte("y")}}
	adapter := NewEmbeddedPodmanAdapter(mgr)

	result, err := adapter.ExecContainer(context.Background(), "cid", ExecOptions{Command: []string{"ls"}})
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
	assert.Equal(t, "x", string(result.Stdout))
	assert.Equal(t, "y", string(result.Stderr))
}

func TestAdapterExec_NotSupported(t *testing.T) {
	adapter := NewEmbeddedPodmanAdapter(&bareManager{})
	_, err := adapter.ExecContainer(context.Background(), "cid", ExecOptions{Command: []string{"ls"}})
	require.ErrorIs(t, err, ErrExecNotSupported)
}

func TestAdapterMetrics_Conversion(t *testing.T) {
	mgr := &fakeOpsManager{stats: &podman.ResourceStats{
		CPUUsagePercent:  7.5,
		MemoryUsedBytes:  2048,
		MemoryLimitBytes: 8192,
		DiskReadBytes:    100,
		DiskWriteBytes:   200,
		NetworkRxBytes:   300,
		NetworkTxBytes:   400,
		UptimeSeconds:    60,
	}}
	adapter := NewEmbeddedPodmanAdapter(mgr)

	stats, err := adapter.ContainerResourceStats(context.Background(), "cid")
	require.NoError(t, err)
	assert.Equal(t, 7.5, stats.CPUUsagePercent)
	assert.Equal(t, uint64(2048), stats.MemoryUsedBytes)
	assert.Equal(t, uint64(8192), stats.MemoryLimitBytes)
	assert.Equal(t, uint64(100), stats.DiskReadBytes)
	assert.Equal(t, uint64(400), stats.NetworkTxBytes)
	assert.Equal(t, uint64(60), stats.UptimeSeconds)
}

func TestAdapterMetrics_NotSupported(t *testing.T) {
	adapter := NewEmbeddedPodmanAdapter(&bareManager{})
	_, err := adapter.ContainerResourceStats(context.Background(), "cid")
	require.ErrorIs(t, err, ErrMetricsNotSupported)
}

func TestAdapterAttach_Conversion(t *testing.T) {
	inner := &fakePodmanSession{out: make(chan podman.AttachChunk, 2)}
	inner.out <- podman.AttachChunk{Stream: "console", Data: []byte("hello")}
	close(inner.out)

	mgr := &fakeOpsManager{session: inner}
	adapter := NewEmbeddedPodmanAdapter(mgr)

	session, err := adapter.AttachContainer(context.Background(), "cid", ExecOptions{})
	require.NoError(t, err)

	chunk := <-session.Output()
	assert.Equal(t, "hello", string(chunk.Data))
	assert.Equal(t, "console", chunk.Stream)
	require.NoError(t, session.Close())
}

func TestAdapterAttach_NotSupported(t *testing.T) {
	adapter := NewEmbeddedPodmanAdapter(&bareManager{})
	_, err := adapter.AttachContainer(context.Background(), "cid", ExecOptions{})
	require.ErrorIs(t, err, ErrAttachNotSupported)
}

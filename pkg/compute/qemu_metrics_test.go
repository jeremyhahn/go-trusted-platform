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

package compute

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOpsOrchestrator builds a QEMU orchestrator with no real VM processes,
// suitable for exercising the VM operational capabilities with seamed host
// primitives.
func newOpsOrchestrator(t *testing.T) *QEMUOrchestrator {
	t.Helper()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()

	orch, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())
	require.NoError(t, err)

	t.Cleanup(func() {
		orch.mu.Lock()
		orch.instances = make(map[string]*qemuInstance)
		orch.mu.Unlock()
		_ = orch.Close()
	})
	return orch
}

// insertVMInstance injects an instance directly (bypassing Create, which would
// exec qemu-img) and drives it to the requested lifecycle state.
func insertVMInstance(t *testing.T, orch *QEMUOrchestrator, id string, running bool, cfg *InstanceConfig) *qemuInstance {
	t.Helper()

	inst := &Instance{
		ID:        id,
		Name:      "test-vm",
		Type:      ComputeTypeVM,
		State:     StateStopped,
		Config:    cfg,
		CreatedAt: time.Now().Add(-time.Minute),
		Metadata:  make(map[string]string),
	}

	qi := &qemuInstance{instance: inst}
	orch.mu.Lock()
	orch.instances[id] = qi
	orch.mu.Unlock()

	require.NoError(t, orch.lifecycle.SetState(id, StateCreating))
	require.NoError(t, orch.lifecycle.SetState(id, StateStopped))
	if running {
		require.NoError(t, orch.lifecycle.SetState(id, StateStarting))
		require.NoError(t, orch.lifecycle.SetState(id, StateRunning))
		inst.State = StateRunning
		inst.PID = 4242
		inst.StartedAt = time.Now().Add(-30 * time.Second)
	}
	return qi
}

func TestGetVMMetrics_HappyPath(t *testing.T) {
	orch := newOpsOrchestrator(t)
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{
		WorkDir:  t.TempDir(),
		DiskPath: "/vms/vm1/disk.qcow2",
		Memory:   2048,
	})

	var cpuCalls atomic.Int64
	restore := swapMetricsSeams(t,
		func(pid int) (uint64, error) {
			// Second sample larger than the first to yield a positive delta.
			if cpuCalls.Add(1) == 1 {
				return 1000, nil
			}
			return 1030, nil
		},
		func(pid int) (uint64, error) { return 512 * 1024 * 1024, nil },
		func(iface string) (uint64, uint64, error) { return 0, 0, os.ErrNotExist },
		func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) ([]qemu.BlockStat, error) {
			return []qemu.BlockStat{
				{NodeName: "hd0", Stats: qemu.BlockStatCounters{RdBytes: 4096, WrBytes: 8192}},
				{NodeName: "node-x", Stats: qemu.BlockStatCounters{RdBytes: 1, WrBytes: 2}},
			}, nil
		},
	)
	defer restore()
	cpuSampleInterval = 5 * time.Millisecond

	metrics, err := orch.GetVMMetrics(context.Background(), "vm1")
	require.NoError(t, err)
	require.NotNil(t, metrics)

	assert.Greater(t, metrics.CPUUsagePercent, 0.0)
	assert.Equal(t, uint64(512), metrics.MemoryUsedMB)
	assert.Equal(t, uint64(2048-512), metrics.MemoryAvailableMB)
	assert.Equal(t, uint64(4097), metrics.DiskReadBytes)
	assert.Equal(t, uint64(8194), metrics.DiskWriteBytes)
	assert.GreaterOrEqual(t, metrics.UptimeSeconds, uint32(30))
}

func TestGetVMMetrics_Errors(t *testing.T) {
	orch := newOpsOrchestrator(t)

	t.Run("empty id", func(t *testing.T) {
		_, err := orch.GetVMMetrics(context.Background(), "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := orch.GetVMMetrics(context.Background(), "nope")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("not running", func(t *testing.T) {
		insertVMInstance(t, orch, "stopped", false, &InstanceConfig{WorkDir: t.TempDir(), Memory: 1024})
		_, err := orch.GetVMMetrics(context.Background(), "stopped")
		assert.ErrorIs(t, err, ErrInstanceNotRunning)
	})

	t.Run("no pid", func(t *testing.T) {
		qi := insertVMInstance(t, orch, "nopid", true, &InstanceConfig{WorkDir: t.TempDir(), Memory: 1024})
		qi.instance.PID = 0
		_, err := orch.GetVMMetrics(context.Background(), "nopid")
		assert.ErrorIs(t, err, ErrVMMetricsUnavailable)
	})

	t.Run("proc read failure", func(t *testing.T) {
		insertVMInstance(t, orch, "badproc", true, &InstanceConfig{WorkDir: t.TempDir(), Memory: 1024})
		restore := swapMetricsSeams(t,
			func(pid int) (uint64, error) { return 0, os.ErrNotExist },
			func(pid int) (uint64, error) { return 0, nil },
			func(iface string) (uint64, uint64, error) { return 0, 0, nil },
			func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) ([]qemu.BlockStat, error) {
				return nil, nil
			},
		)
		defer restore()
		_, err := orch.GetVMMetrics(context.Background(), "badproc")
		assert.ErrorIs(t, err, ErrVMMetricsUnavailable)
	})
}

func TestSampleCPUPercent_ContextCancelled(t *testing.T) {
	orch := newOpsOrchestrator(t)
	restore := swapMetricsSeams(t,
		func(pid int) (uint64, error) { return 1000, nil },
		func(pid int) (uint64, error) { return 0, nil },
		func(iface string) (uint64, uint64, error) { return 0, 0, nil },
		func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) ([]qemu.BlockStat, error) {
			return nil, nil
		},
	)
	defer restore()
	cpuSampleInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := orch.sampleCPUPercent(ctx, 1)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDefaultReadProcParsers(t *testing.T) {
	self := os.Getpid()

	jiffies, err := defaultReadProcCPUJiffies(self)
	require.NoError(t, err)
	_ = jiffies // may legitimately be 0 for a short-lived process

	rss, err := defaultReadProcRSSBytes(self)
	require.NoError(t, err)
	assert.Greater(t, rss, uint64(0))

	_, err = defaultReadProcCPUJiffies(-1)
	assert.Error(t, err)

	_, err = defaultReadProcRSSBytes(-1)
	assert.Error(t, err)
}

func TestReadCounterFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rx_bytes")
	require.NoError(t, os.WriteFile(path, []byte("123456\n"), 0o644))

	v, err := readCounterFile(path)
	require.NoError(t, err)
	assert.Equal(t, uint64(123456), v)

	_, err = readCounterFile(filepath.Join(dir, "missing"))
	assert.Error(t, err)
}

func TestDefaultReadNetIfaceStats_Missing(t *testing.T) {
	_, _, err := defaultReadNetIfaceStats("nonexistent-iface-xyz")
	assert.Error(t, err)
}

// swapMetricsSeams installs metric collection seams and returns a restorer.
func swapMetricsSeams(
	t *testing.T,
	cpu func(int) (uint64, error),
	rss func(int) (uint64, error),
	net func(string) (uint64, uint64, error),
	block func(context.Context, *QEMUOrchestrator, *qemuInstance) ([]qemu.BlockStat, error),
) func() {
	t.Helper()
	origCPU, origRSS, origNet, origBlock, origInterval :=
		readProcCPUJiffies, readProcRSSBytes, readNetIfaceStats, vmBlockStatsFor, cpuSampleInterval
	readProcCPUJiffies = cpu
	readProcRSSBytes = rss
	readNetIfaceStats = net
	vmBlockStatsFor = block
	return func() {
		readProcCPUJiffies = origCPU
		readProcRSSBytes = origRSS
		readNetIfaceStats = origNet
		vmBlockStatsFor = origBlock
		cpuSampleInterval = origInterval
	}
}

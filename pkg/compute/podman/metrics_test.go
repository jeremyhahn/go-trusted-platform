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

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCgroupFS lays out a faked proc and cgroup v2 tree for a container PID and
// installs it into the metrics seams. It returns the PID and restores the
// seams via t.Cleanup.
func fakeCgroupFS(t *testing.T, pid int, files map[string]string) {
	t.Helper()

	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	cgroup := filepath.Join(root, "cgroup")

	// /proc/<pid>/cgroup points at the "mygroup" cgroup path.
	pidDir := filepath.Join(proc, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(filepath.Join(pidDir, "net"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/mygroup\n"), 0o644))

	if netDev, ok := files["net/dev"]; ok {
		require.NoError(t, os.WriteFile(filepath.Join(pidDir, "net", "dev"), []byte(netDev), 0o644))
	}

	cgDir := filepath.Join(cgroup, "mygroup")
	require.NoError(t, os.MkdirAll(cgDir, 0o755))
	for name, content := range files {
		if name == "net/dev" {
			continue
		}
		require.NoError(t, os.WriteFile(filepath.Join(cgDir, name), []byte(content), 0o644))
	}

	origProc, origCgroup, origWindow := procRoot, cgroupRoot, cpuSampleWindow
	procRoot = proc
	cgroupRoot = cgroup
	cpuSampleWindow = time.Millisecond
	t.Cleanup(func() {
		procRoot = origProc
		cgroupRoot = origCgroup
		cpuSampleWindow = origWindow
	})
}

func TestRuntimeStats_Success(t *testing.T) {
	rt := newTestRuntime(t)
	state, err := rt.CreateContainer(context.Background(), &ContainerConfig{Name: "stats-ok", Image: "alpine:latest"})
	require.NoError(t, err)

	pid := 4242
	state.PID = pid
	started := time.Now().Add(-90 * time.Second)
	state.StartedAt = &started

	fakeCgroupFS(t, pid, map[string]string{
		"cpu.stat":       "usage_usec 1000000\nuser_usec 500000\nsystem_usec 500000\n",
		"memory.current": "104857600\n",
		"memory.max":     "268435456\n",
		"io.stat":        "8:0 rbytes=2048 wbytes=4096 rios=1 wios=2\n8:16 rbytes=1024 wbytes=512\n",
		"net/dev": "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo:     100       1    0    0    0     0          0         0     100       1    0    0    0     0       0          0\n" +
			"  eth0:    5000      10    0    0    0     0          0         0    9000      12    0    0    0     0       0          0\n",
	})

	stats, err := rt.Stats(context.Background(), state.ID)
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, uint64(104857600), stats.MemoryUsedBytes)
	assert.Equal(t, uint64(268435456), stats.MemoryLimitBytes)
	assert.Equal(t, uint64(2048+1024), stats.DiskReadBytes)
	assert.Equal(t, uint64(4096+512), stats.DiskWriteBytes)
	// Loopback is excluded; only eth0 counts.
	assert.Equal(t, uint64(5000), stats.NetworkRxBytes)
	assert.Equal(t, uint64(9000), stats.NetworkTxBytes)
	assert.GreaterOrEqual(t, stats.UptimeSeconds, uint64(89))
}

func TestRuntimeStats_UnlimitedMemory(t *testing.T) {
	rt := newTestRuntime(t)
	state, err := rt.CreateContainer(context.Background(), &ContainerConfig{Name: "stats-unlimited", Image: "alpine:latest"})
	require.NoError(t, err)
	state.PID = 4243

	fakeCgroupFS(t, 4243, map[string]string{
		"cpu.stat":       "usage_usec 0\n",
		"memory.current": "1000\n",
		"memory.max":     "max\n",
	})

	stats, err := rt.Stats(context.Background(), state.ID)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), stats.MemoryLimitBytes)
	assert.Equal(t, uint64(1000), stats.MemoryUsedBytes)
}

func TestRuntimeStats_MissingContainer(t *testing.T) {
	rt := newTestRuntime(t)
	_, err := rt.Stats(context.Background(), "nope")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotFound)
}

func TestRuntimeStats_NoPID(t *testing.T) {
	rt := newTestRuntime(t)
	state, err := rt.CreateContainer(context.Background(), &ContainerConfig{Name: "stats-nopid", Image: "alpine:latest"})
	require.NoError(t, err)
	state.PID = 0 // never started; getContainerPID will fail against the fake runtime

	_, err = rt.Stats(context.Background(), state.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContainerNotRunning)
}

func TestRuntimeStats_CgroupPathAbsent(t *testing.T) {
	rt := newTestRuntime(t)
	state, err := rt.CreateContainer(context.Background(), &ContainerConfig{Name: "stats-nocgroup", Image: "alpine:latest"})
	require.NoError(t, err)
	state.PID = 9999

	// Point the seams at an empty tree so /proc/<pid>/cgroup does not exist.
	empty := t.TempDir()
	origProc, origCgroup := procRoot, cgroupRoot
	procRoot = filepath.Join(empty, "proc")
	cgroupRoot = filepath.Join(empty, "cgroup")
	t.Cleanup(func() { procRoot, cgroupRoot = origProc, origCgroup })

	_, err = rt.Stats(context.Background(), state.ID)
	require.Error(t, err)
}

func TestRuntimeStats_CPUPercent(t *testing.T) {
	// A cpu.stat whose usage_usec advances between samples yields a non-zero
	// percentage. The seam replaces the file reader with an advancing counter.
	rt := newTestRuntime(t)
	state, err := rt.CreateContainer(context.Background(), &ContainerConfig{Name: "stats-cpu", Image: "alpine:latest"})
	require.NoError(t, err)
	state.PID = 5555

	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	cgroup := filepath.Join(root, "cgroup")
	pidDir := filepath.Join(proc, strconv.Itoa(5555))
	require.NoError(t, os.MkdirAll(pidDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/g\n"), 0o644))
	cgDir := filepath.Join(cgroup, "g")
	require.NoError(t, os.MkdirAll(cgDir, 0o755))
	cpuStatPath := filepath.Join(cgDir, "cpu.stat")
	require.NoError(t, os.WriteFile(cpuStatPath, []byte("usage_usec 0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cgDir, "memory.current"), []byte("0\n"), 0o644))

	origProc, origCgroup := procRoot, cgroupRoot
	procRoot, cgroupRoot = proc, cgroup
	t.Cleanup(func() { procRoot, cgroupRoot = origProc, origCgroup })

	// The sampling window runs on synctest time (#284): the counter
	// advances halfway through it, after the first read and before the
	// second, every time.
	synctest.Test(t, func(t *testing.T) {
		go func() {
			timer := time.NewTimer(cpuSampleWindow / 2)
			<-timer.C
			usage := cpuSampleWindow.Microseconds() / 10
			if err := os.WriteFile(cpuStatPath, []byte("usage_usec "+strconv.FormatInt(usage, 10)+"\n"), 0o644); err != nil {
				t.Errorf("advance cpu.stat: %v", err)
			}
		}()

		stats, err := rt.Stats(context.Background(), state.ID)
		require.NoError(t, err)
		// A tenth of the window consumed => 10% CPU.
		assert.InDelta(t, 10.0, stats.CPUUsagePercent, 1e-9)
	})
}

func TestReadIOStat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "io.stat")
	require.NoError(t, os.WriteFile(path, []byte("8:0 rbytes=10 wbytes=20\n8:1 rbytes=5 wbytes=6\n"), 0o644))

	r, w := readIOStat(path)
	assert.Equal(t, uint64(15), r)
	assert.Equal(t, uint64(26), w)

	// Missing file yields zeros.
	r, w = readIOStat(filepath.Join(dir, "absent"))
	assert.Equal(t, uint64(0), r)
	assert.Equal(t, uint64(0), w)
}

func TestReadMemoryMax(t *testing.T) {
	dir := t.TempDir()

	limited := filepath.Join(dir, "limited")
	require.NoError(t, os.WriteFile(limited, []byte("1024\n"), 0o644))
	v, ok := readMemoryMax(limited)
	assert.True(t, ok)
	assert.Equal(t, uint64(1024), v)

	unlimited := filepath.Join(dir, "unlimited")
	require.NoError(t, os.WriteFile(unlimited, []byte("max\n"), 0o644))
	v, ok = readMemoryMax(unlimited)
	assert.True(t, ok)
	assert.Equal(t, uint64(0), v)
}

func TestManagerResourceStats_NotInitialized(t *testing.T) {
	m := &podmanManager{config: DefaultManagerConfig(), logger: newTestRuntime(t).logger}
	_, err := m.ResourceStats(context.Background(), "cid")
	require.ErrorIs(t, err, ErrClientNotConnected)
}

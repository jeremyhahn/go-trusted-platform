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
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrCgroupUnavailable is returned when a container's cgroup v2 hierarchy
// cannot be located (e.g. the container is not running).
var ErrCgroupUnavailable = errors.New("container cgroup unavailable")

// ErrMetricsNotSupported is returned when the backend cannot report container
// metrics.
var ErrMetricsNotSupported = errors.New("container metrics not supported by backend")

// Metrics collection seams. They are package-level variables (defaulting to the
// real Linux pseudo-filesystems) so tests can point them at a faked cgroup and
// proc tree without host mutation.
var (
	// procRoot is the mount point of the proc filesystem.
	procRoot = "/proc"

	// cgroupRoot is the mount point of the unified cgroup v2 hierarchy.
	cgroupRoot = "/sys/fs/cgroup"

	// cpuSampleWindow is the interval between the two cpu.stat samples used to
	// derive the instantaneous CPU usage percentage.
	cpuSampleWindow = 100 * time.Millisecond
)

// ResourceStats is a point-in-time resource-usage snapshot for a container,
// derived from its cgroup v2 controllers (cpu.stat, memory.current,
// memory.max, io.stat) and its network namespace (/proc/<pid>/net/dev).
type ResourceStats struct {
	// CPUUsagePercent is the CPU utilisation over the sample window, summed
	// across all cores (so it may exceed 100 on multi-core containers).
	CPUUsagePercent float64

	// MemoryUsedBytes is the current memory charge (memory.current).
	MemoryUsedBytes uint64

	// MemoryLimitBytes is the memory hard limit (memory.max); 0 means unlimited.
	MemoryLimitBytes uint64

	// DiskReadBytes is the total bytes read across block devices (io.stat).
	DiskReadBytes uint64

	// DiskWriteBytes is the total bytes written across block devices (io.stat).
	DiskWriteBytes uint64

	// NetworkRxBytes is the total bytes received across non-loopback interfaces.
	NetworkRxBytes uint64

	// NetworkTxBytes is the total bytes transmitted across non-loopback interfaces.
	NetworkTxBytes uint64

	// UptimeSeconds is the container's uptime since it was started.
	UptimeSeconds uint64
}

// MetricsReader is the capability of reporting per-container resource metrics.
// The embedded podmanManager satisfies it.
type MetricsReader interface {
	ResourceStats(ctx context.Context, id string) (*ResourceStats, error)
}

// Stats reads a resource-usage snapshot for a running container from its
// cgroup v2 controllers and network namespace.
func (r *Runtime) Stats(ctx context.Context, id string) (*ResourceStats, error) {
	state, err := r.lookupContainer(id)
	if err != nil {
		return nil, err
	}

	pid := state.PID
	if pid <= 0 {
		pid, _ = r.getContainerPID(ctx, state.ID)
	}
	if pid <= 0 {
		return nil, NewContainerError(id, "metrics", ErrContainerNotRunning)
	}

	cgroupDir, err := cgroupDirForPID(pid)
	if err != nil {
		return nil, NewContainerError(id, "metrics", err)
	}

	stats := &ResourceStats{}

	// CPU usage percent: two cpu.stat samples separated by cpuSampleWindow.
	usage0, ok0 := readCPUUsageUsec(cgroupDir)
	if ok0 {
		timer := time.NewTimer(cpuSampleWindow)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		usage1, ok1 := readCPUUsageUsec(cgroupDir)
		if ok1 && usage1 >= usage0 {
			windowUsec := float64(cpuSampleWindow.Microseconds())
			if windowUsec > 0 {
				stats.CPUUsagePercent = float64(usage1-usage0) / windowUsec * 100.0
			}
		}
	}

	// Memory.
	if v, ok := readCgroupUint(filepath.Join(cgroupDir, "memory.current")); ok {
		stats.MemoryUsedBytes = v
	}
	if v, ok := readMemoryMax(filepath.Join(cgroupDir, "memory.max")); ok {
		stats.MemoryLimitBytes = v
	}

	// Block I/O.
	stats.DiskReadBytes, stats.DiskWriteBytes = readIOStat(filepath.Join(cgroupDir, "io.stat"))

	// Network (per network namespace, via the container PID).
	stats.NetworkRxBytes, stats.NetworkTxBytes = readNetDev(filepath.Join(procRoot, strconv.Itoa(pid), "net", "dev"))

	// Uptime.
	if state.StartedAt != nil {
		elapsed := time.Since(*state.StartedAt)
		if elapsed > 0 {
			stats.UptimeSeconds = uint64(elapsed.Seconds())
		}
	}

	return stats, nil
}

// cgroupDirForPID resolves a process's cgroup v2 directory by parsing
// /proc/<pid>/cgroup (the unified "0::<path>" line) and joining it onto the
// cgroup mount point.
func cgroupDirForPID(pid int) (string, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", &WrappedError{Msg: "read " + path, Err: err}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 unified hierarchy: "0::<relative-path>".
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimPrefix(line, "0::")
			return filepath.Join(cgroupRoot, rel), nil
		}
	}

	return "", ErrCgroupUnavailable
}

// readCPUUsageUsec reads the cumulative CPU usage (usage_usec) from a cgroup's
// cpu.stat file.
func readCPUUsageUsec(cgroupDir string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(cgroupDir, "cpu.stat"))
	if err != nil {
		return 0, false
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "usage_usec" {
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// readCgroupUint reads a single unsigned integer value from a cgroup file.
func readCgroupUint(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readMemoryMax reads memory.max, mapping the sentinel value "max" (unlimited)
// to 0.
func readMemoryMax(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return 0, true
	}
	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readIOStat sums the rbytes and wbytes counters across all block devices in a
// cgroup's io.stat file. Each line is "MAJ:MIN key=value key=value ...".
func readIOStat(path string) (readBytes, writeBytes uint64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		for _, field := range strings.Fields(scanner.Text()) {
			key, value, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "rbytes":
				readBytes += v
			case "wbytes":
				writeBytes += v
			}
		}
	}
	return readBytes, writeBytes
}

// readNetDev sums the received and transmitted byte counters across all
// non-loopback interfaces in a /proc/<pid>/net/dev file.
func readNetDev(path string) (rxBytes, txBytes uint64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		name, rest, found := strings.Cut(line, ":")
		if !found {
			// Header lines ("Inter-|   Receive ...") have no colon-delimited iface.
			continue
		}
		iface := strings.TrimSpace(name)
		if iface == "" || iface == "lo" {
			continue
		}
		fields := strings.Fields(rest)
		// Columns: rx_bytes(0) ... tx_bytes(8).
		if len(fields) < 9 {
			continue
		}
		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			rxBytes += v
		}
		if v, err := strconv.ParseUint(fields[8], 10, 64); err == nil {
			txBytes += v
		}
	}
	return rxBytes, txBytes
}

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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// Seams for VM metric collection. They are package-level function variables so
// unit tests can substitute host primitives without a real VM. Production code
// uses the default implementations, which read /proc, /sys, and QMP.
var (
	// readProcCPUJiffies returns the cumulative CPU time (utime+stime) of a
	// process in clock ticks.
	readProcCPUJiffies = defaultReadProcCPUJiffies

	// readProcRSSBytes returns the resident set size of a process in bytes.
	readProcRSSBytes = defaultReadProcRSSBytes

	// readNetIfaceStats returns the cumulative rx/tx byte counters of a host
	// network interface.
	readNetIfaceStats = defaultReadNetIfaceStats

	// vmBlockStatsFor returns the QMP block I/O counters for an instance.
	vmBlockStatsFor = defaultVMBlockStatsFor

	// cpuSampleInterval is the delta window used to derive CPU utilization.
	cpuSampleInterval = 120 * time.Millisecond

	// clockTicksPerSecond is the kernel USER_HZ (sysconf(_SC_CLK_TCK)); Linux
	// x86_64 uses 100.
	clockTicksPerSecond = int64(100)
)

// GetVMMetrics samples a running VM's CPU, memory, disk, and network
// utilization from host primitives: CPU from /proc/<pid>/stat sampled over a
// short interval, memory (RSS) from /proc/<pid>/statm, disk I/O from the QMP
// query-blockstats command, and network I/O from the host tap interface's
// /sys/class/net statistics. Uptime is measured from the instance's last
// transition to the running state.
func (o *QEMUOrchestrator) GetVMMetrics(ctx context.Context, instanceID string) (*VMMetrics, error) {
	if instanceID == "" {
		return nil, ErrInvalidInstanceID
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return nil, ErrInstanceNotFound
	}

	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return nil, err
	}
	if state != StateRunning {
		return nil, &SentinelCauseError{
			Sentinel: ErrInstanceNotRunning,
			Cause:    &MessageError{Msg: "VM metrics require a running VM"},
		}
	}

	inst.mu.Lock()
	pid := inst.instance.PID
	startedAt := inst.instance.StartedAt
	if startedAt.IsZero() {
		startedAt = inst.instance.CreatedAt
	}
	var memTotalMB uint64
	if inst.instance.Config != nil && inst.instance.Config.Memory > 0 {
		memTotalMB = uint64(inst.instance.Config.Memory)
	}
	var tapName string
	if inst.ovsNetwork != nil {
		tapName = inst.ovsNetwork.GetTAPName()
	}
	inst.mu.Unlock()

	if pid <= 0 {
		return nil, &SentinelCauseError{
			Sentinel: ErrVMMetricsUnavailable,
			Cause:    &MessageError{Msg: "VM has no process ID"},
		}
	}

	metrics := &VMMetrics{}

	cpu, err := o.sampleCPUPercent(ctx, pid)
	if err != nil {
		return nil, err
	}
	metrics.CPUUsagePercent = cpu

	rssBytes, err := readProcRSSBytes(pid)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrVMMetricsUnavailable, Cause: err}
	}
	metrics.MemoryUsedMB = rssBytes / (1024 * 1024)
	if memTotalMB > metrics.MemoryUsedMB {
		metrics.MemoryAvailableMB = memTotalMB - metrics.MemoryUsedMB
	}

	// Disk I/O is best-effort: a monitor hiccup must not fail the whole sample.
	if stats, statErr := vmBlockStatsFor(ctx, o, inst); statErr == nil {
		var rd, wr int64
		for i := range stats {
			rd += stats[i].Stats.RdBytes
			wr += stats[i].Stats.WrBytes
		}
		metrics.DiskReadBytes = uint64(rd)
		metrics.DiskWriteBytes = uint64(wr)
	} else {
		o.logger.Warnf("VM metrics: block stats unavailable for %s: %v", instanceID, statErr)
	}

	// Network I/O is best-effort and read from the host tap interface. The tap
	// counters are from the host's perspective, so they are inverted relative
	// to the guest: bytes the host transmits onto the tap are received by the
	// guest, and vice versa.
	if tapName != "" {
		if rx, tx, netErr := readNetIfaceStats(tapName); netErr == nil {
			metrics.NetworkRxBytes = tx
			metrics.NetworkTxBytes = rx
		} else {
			o.logger.Warnf("VM metrics: tap stats unavailable for %s (%s): %v", instanceID, tapName, netErr)
		}
	}

	uptime := time.Since(startedAt).Seconds()
	if uptime < 0 {
		uptime = 0
	}
	metrics.UptimeSeconds = uint32(uptime)

	return metrics, nil
}

// sampleCPUPercent derives CPU utilization by comparing the process's
// cumulative CPU time across a short interval. It waits on a timer channel
// (never time.Sleep) so the sample honors context cancellation.
func (o *QEMUOrchestrator) sampleCPUPercent(ctx context.Context, pid int) (float64, error) {
	j0, err := readProcCPUJiffies(pid)
	if err != nil {
		return 0, &SentinelCauseError{Sentinel: ErrVMMetricsUnavailable, Cause: err}
	}
	start := time.Now()

	timer := time.NewTimer(cpuSampleInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
	}

	j1, err := readProcCPUJiffies(pid)
	if err != nil {
		return 0, &SentinelCauseError{Sentinel: ErrVMMetricsUnavailable, Cause: err}
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 || j1 < j0 {
		return 0, nil
	}
	cpuSeconds := float64(j1-j0) / float64(clockTicksPerSecond)
	return cpuSeconds / elapsed * 100.0, nil
}

// defaultReadProcCPUJiffies parses /proc/<pid>/stat and returns utime+stime in
// clock ticks. The comm field (field 2) may contain spaces and parentheses, so
// parsing resumes after the final ')'.
func defaultReadProcCPUJiffies(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	content := string(data)
	rparen := strings.LastIndexByte(content, ')')
	if rparen < 0 || rparen+2 >= len(content) {
		return 0, &MessageError{Msg: "malformed /proc/<pid>/stat: missing comm delimiter"}
	}
	// Fields after comm start at index 3 (state). utime is field 14 and stime
	// field 15 overall, i.e. indices 11 and 12 in the post-comm slice.
	fields := strings.Fields(content[rparen+2:])
	if len(fields) < 13 {
		return 0, &MessageError{Msg: "malformed /proc/<pid>/stat: too few fields"}
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, &WrappedError{Msg: "parse utime", Err: err}
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, &WrappedError{Msg: "parse stime", Err: err}
	}
	return utime + stime, nil
}

// defaultReadProcRSSBytes parses /proc/<pid>/statm and returns the resident set
// size in bytes (resident pages * page size).
func defaultReadProcRSSBytes(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, &MessageError{Msg: "malformed /proc/<pid>/statm"}
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, &WrappedError{Msg: "parse resident pages", Err: err}
	}
	return residentPages * uint64(os.Getpagesize()), nil
}

// defaultReadNetIfaceStats reads the cumulative rx/tx byte counters for a host
// network interface from /sys/class/net/<iface>/statistics.
func defaultReadNetIfaceStats(iface string) (rx, tx uint64, err error) {
	rx, err = readCounterFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface))
	if err != nil {
		return 0, 0, err
	}
	tx, err = readCounterFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface))
	if err != nil {
		return 0, 0, err
	}
	return rx, tx, nil
}

// readCounterFile reads a single unsigned integer from a sysfs counter file.
func readCounterFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// defaultVMBlockStatsFor connects the instance's QMP monitor (reusing an
// existing connection) and returns the block I/O counters.
func defaultVMBlockStatsFor(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) ([]qemu.BlockStat, error) {
	mon := inst.vm.Monitor()
	if mon == nil || !mon.IsConnected() {
		if err := inst.vm.ConnectMonitor(ctx); err != nil {
			return nil, &WrappedError{Msg: "failed to connect QMP monitor", Err: err}
		}
		mon = inst.vm.Monitor()
	}
	return mon.BlockStats(ctx)
}

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

// Package sysstats reports OS-level CPU, memory, and disk usage so the
// platform daemon's REST handlers can populate dashboard widgets without
// pulling in a heavyweight monitoring dependency.
//
// CPU usage requires two samples taken some time apart, so callers either
// use a long-lived [Sampler] (recommended for daemons) or accept that the
// first call to [Sampler.Snapshot] returns 0% and seeds the baseline.
package sysstats

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ErrUnsupported is returned when the host kernel does not expose the
// data sources sysstats relies on (notably /proc on non-Linux systems).
var ErrUnsupported = errors.New("sysstats: kernel data sources unavailable")

var (
	// ErrProcStatEmpty is returned when /proc/stat has no lines.
	ErrProcStatEmpty = errors.New("sysstats: /proc/stat is empty")
	// ErrProcStatNoAggregateCPU is returned when the first /proc/stat line
	// is not the aggregate "cpu" line.
	ErrProcStatNoAggregateCPU = errors.New("sysstats: /proc/stat first line is not aggregate cpu")
	// ErrMemTotalMissing is returned when /proc/meminfo has no MemTotal.
	ErrMemTotalMissing = errors.New("sysstats: MemTotal not found in /proc/meminfo")
)

// procRoot is the procfs directory the CPU and memory samplers read.
// Overridable seam for tests; defaults to /proc.
var procRoot = "/proc"

// procSupported reports whether the host kernel exposes procfs.
// Overridable seam for tests; defaults to true on Linux only.
var procSupported = runtime.GOOS == "linux"

// Snapshot is a single sample of CPU/memory/disk pressure.
type Snapshot struct {
	CPUPercent    float64
	MemoryPercent float64
	DiskPercent   float64
	DiskPath      string
	Timestamp     time.Time
}

// Sampler maintains the state required to compute deltas between two
// /proc/stat reads. The zero value is ready to use; callers should
// stash a single Sampler on the daemon and reuse it.
type Sampler struct {
	mu        sync.Mutex
	prevTotal uint64
	prevIdle  uint64
	diskPath  string
}

// NewSampler returns a Sampler that watches diskPath for filesystem
// usage. An empty diskPath defaults to "/".
func NewSampler(diskPath string) *Sampler {
	if diskPath == "" {
		diskPath = "/"
	}
	return &Sampler{diskPath: diskPath}
}

// Snapshot collects a sample. The returned Snapshot is always non-nil
// when err is nil, but values may be zero on the first call (CPU
// requires a baseline) or when individual subsystems are unavailable.
func (s *Sampler) Snapshot() (Snapshot, error) {
	now := time.Now()
	cpu, err := s.cpuPercent()
	if err != nil && !errors.Is(err, ErrUnsupported) {
		return Snapshot{}, err
	}

	mem, err := memoryPercent()
	if err != nil && !errors.Is(err, ErrUnsupported) {
		return Snapshot{}, err
	}

	disk, err := diskPercent(s.diskPath)
	if err != nil {
		return Snapshot{}, err
	}

	return Snapshot{
		CPUPercent:    cpu,
		MemoryPercent: mem,
		DiskPercent:   disk,
		DiskPath:      s.diskPath,
		Timestamp:     now,
	}, nil
}

// cpuPercent reads /proc/stat and returns the percentage of non-idle
// time since the last call. The first call seeds the baseline and
// returns 0%.
func (s *Sampler) cpuPercent() (float64, error) {
	if !procSupported {
		return 0, ErrUnsupported
	}

	total, idle, err := readProcStatCPU()
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.prevTotal == 0 {
		s.prevTotal = total
		s.prevIdle = idle
		return 0, nil
	}

	deltaTotal := total - s.prevTotal
	deltaIdle := idle - s.prevIdle
	s.prevTotal = total
	s.prevIdle = idle

	if deltaTotal == 0 {
		return 0, nil
	}

	used := deltaTotal - deltaIdle
	return float64(used) / float64(deltaTotal) * 100, nil
}

// readProcStatCPU returns (totalJiffies, idleJiffies) from the
// aggregate "cpu" line in /proc/stat.
func readProcStatCPU() (uint64, uint64, error) {
	f, err := os.Open(filepath.Join(procRoot, "stat"))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, 0, ErrProcStatEmpty
	}

	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return 0, 0, ErrProcStatNoAggregateCPU
	}

	fields := strings.Fields(line)[1:]
	var total uint64
	var idle uint64
	for i, f := range fields {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, 0, err
		}
		total += v
		// /proc/stat layout: user nice system idle iowait irq softirq steal guest guest_nice
		// idle is index 3, iowait (also idle from the scheduler's view) is 4.
		if i == 3 || i == 4 {
			idle += v
		}
	}
	return total, idle, nil
}

// memoryPercent reads /proc/meminfo and returns
// (MemTotal - MemAvailable) / MemTotal * 100.
func memoryPercent() (float64, error) {
	if !procSupported {
		return 0, ErrUnsupported
	}

	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var total uint64
	var available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			available = parseMeminfoKB(line)
		}
		if total != 0 && available != 0 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, ErrMemTotalMissing
	}
	if available > total {
		available = total
	}

	used := total - available
	return float64(used) / float64(total) * 100, nil
}

// parseMeminfoKB extracts the kB value from a line like
// "MemTotal:       16384000 kB". Returns 0 on malformed input.
func parseMeminfoKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// diskPercent returns the used-percentage for the filesystem hosting
// path. It uses statfs(2) and works on every Unix the platform builds for.
func diskPercent(path string) (float64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	if total == 0 {
		return 0, nil
	}
	free := stat.Bfree * uint64(stat.Bsize)
	if free > total {
		free = total
	}
	used := total - free
	return float64(used) / float64(total) * 100, nil
}

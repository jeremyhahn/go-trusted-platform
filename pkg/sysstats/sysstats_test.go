// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC

package sysstats

import (
	"bufio"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const (
	// statIdle is a /proc/stat aggregate line: total 1000 jiffies, 800 idle
	// (idle 700 + iowait 100).
	statIdle = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 100 0 100 700 100 0 0 0 0 0\n"
	// statBusy follows statIdle: total +600 jiffies, idle +300, so 50% busy.
	statBusy = "cpu  250 0 250 1000 100 0 0 0 0 0\n"
	// meminfo75 is a /proc/meminfo with 75% of memory in use.
	meminfo75 = "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    250 kB\n"
)

// useProc points the samplers at an empty temp procfs root for one test.
// The package seams make these tests unsafe to run in parallel.
func useProc(t *testing.T) string {
	t.Helper()
	savedRoot, savedSupported := procRoot, procSupported
	procRoot, procSupported = t.TempDir(), true
	t.Cleanup(func() { procRoot, procSupported = savedRoot, savedSupported })
	return procRoot
}

// useProcFiles points the samplers at a temp procfs holding stat and meminfo.
func useProcFiles(t *testing.T, stat, meminfo string) string {
	t.Helper()
	root := useProc(t)
	writeProcFile(t, root, "stat", stat)
	writeProcFile(t, root, "meminfo", meminfo)
	return root
}

func writeProcFile(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestProcSeamDefaults(t *testing.T) {
	if procRoot != "/proc" {
		t.Errorf("procRoot = %q, want /proc", procRoot)
	}
	if procSupported != (runtime.GOOS == "linux") {
		t.Errorf("procSupported = %v, want %v on %s", procSupported, runtime.GOOS == "linux", runtime.GOOS)
	}
}

func TestSamplerSnapshotPopulatesDisk(t *testing.T) {
	useProcFiles(t, statIdle, meminfo75)
	diskPath := t.TempDir()

	s := NewSampler(diskPath)
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if snap.DiskPath != diskPath {
		t.Errorf("expected DiskPath %q, got %q", diskPath, snap.DiskPath)
	}
	if snap.DiskPercent < 0 || snap.DiskPercent > 100 {
		t.Errorf("disk percent out of range: %f", snap.DiskPercent)
	}
	if snap.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestSamplerSnapshotCPUSeedsBaseline(t *testing.T) {
	root := useProcFiles(t, statIdle, meminfo75)
	s := NewSampler(t.TempDir())

	first, err := s.Snapshot()
	if err != nil {
		t.Fatalf("first Snapshot returned error: %v", err)
	}
	if first.CPUPercent != 0 {
		t.Errorf("expected first CPU sample to be 0, got %f", first.CPUPercent)
	}

	writeProcFile(t, root, "stat", statBusy)
	second, err := s.Snapshot()
	if err != nil {
		t.Fatalf("second Snapshot returned error: %v", err)
	}
	if second.CPUPercent != 50 {
		t.Errorf("expected second CPU sample to be 50, got %f", second.CPUPercent)
	}

	// No jiffies elapsed since the last read.
	third, err := s.Snapshot()
	if err != nil {
		t.Fatalf("third Snapshot returned error: %v", err)
	}
	if third.CPUPercent != 0 {
		t.Errorf("expected an unchanged /proc/stat to read 0, got %f", third.CPUPercent)
	}
}

func TestSamplerSnapshotMemory(t *testing.T) {
	useProcFiles(t, statIdle, meminfo75)

	snap, err := NewSampler(t.TempDir()).Snapshot()
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if snap.MemoryPercent != 75 {
		t.Errorf("expected memory percent 75, got %f", snap.MemoryPercent)
	}
}

func TestSamplerSnapshotUnsupportedKernel(t *testing.T) {
	useProc(t)
	procSupported = false

	snap, err := NewSampler(t.TempDir()).Snapshot()
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if snap.CPUPercent != 0 || snap.MemoryPercent != 0 {
		t.Errorf("expected zero CPU and memory without procfs, got %f and %f", snap.CPUPercent, snap.MemoryPercent)
	}
}

func TestSamplerSnapshotErrors(t *testing.T) {
	t.Run("cpu", func(t *testing.T) {
		root := useProc(t)
		writeProcFile(t, root, "meminfo", meminfo75)

		_, err := NewSampler(t.TempDir()).Snapshot()
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected a missing /proc/stat error, got %v", err)
		}
	})

	t.Run("memory", func(t *testing.T) {
		root := useProc(t)
		writeProcFile(t, root, "stat", statIdle)

		_, err := NewSampler(t.TempDir()).Snapshot()
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected a missing /proc/meminfo error, got %v", err)
		}
	})

	t.Run("disk", func(t *testing.T) {
		useProcFiles(t, statIdle, meminfo75)

		_, err := NewSampler(filepath.Join(t.TempDir(), "missing")).Snapshot()
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected a missing disk path error, got %v", err)
		}
	})
}

func TestReadProcStatCPU(t *testing.T) {
	useProcFiles(t, statIdle, meminfo75)

	total, idle, err := readProcStatCPU()
	if err != nil {
		t.Fatalf("readProcStatCPU returned error: %v", err)
	}
	if total != 1000 || idle != 800 {
		t.Errorf("readProcStatCPU() = (%d, %d), want (1000, 800)", total, idle)
	}
}

func TestReadProcStatCPUErrors(t *testing.T) {
	tests := []struct {
		name string
		stat string
		want error
	}{
		{"empty", "", ErrProcStatEmpty},
		{"no aggregate line", "cpu0 100 0 100 700 100 0 0 0 0 0\n", ErrProcStatNoAggregateCPU},
		{"bad counter", "cpu  100 x 100 700\n", strconv.ErrSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useProcFiles(t, tt.stat, meminfo75)
			if _, _, err := readProcStatCPU(); !errors.Is(err, tt.want) {
				t.Errorf("readProcStatCPU() error = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		useProc(t)
		if _, _, err := readProcStatCPU(); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("readProcStatCPU() error = %v, want a not-exist error", err)
		}
	})
}

func TestMemoryPercent(t *testing.T) {
	tests := []struct {
		name    string
		meminfo string
		want    float64
	}{
		{"in use", meminfo75, 75},
		{"available above total", "MemTotal: 1000 kB\nMemAvailable: 2000 kB\n", 0},
		{"no MemAvailable", "MemTotal: 1000 kB\n", 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useProcFiles(t, statIdle, tt.meminfo)
			got, err := memoryPercent()
			if err != nil {
				t.Fatalf("memoryPercent returned error: %v", err)
			}
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("memoryPercent() = %f, want %f", got, tt.want)
			}
		})
	}
}

func TestMemoryPercentErrors(t *testing.T) {
	tests := []struct {
		name    string
		meminfo string
		want    error
	}{
		{"no MemTotal", "MemFree: 100 kB\nMemAvailable: 250 kB\n", ErrMemTotalMissing},
		{"line too long", strings.Repeat("x", bufio.MaxScanTokenSize+1) + "\n" + meminfo75, bufio.ErrTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useProcFiles(t, statIdle, tt.meminfo)
			if _, err := memoryPercent(); !errors.Is(err, tt.want) {
				t.Errorf("memoryPercent() error = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		useProc(t)
		if _, err := memoryPercent(); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("memoryPercent() error = %v, want a not-exist error", err)
		}
	})
}

func TestNewSamplerDefaultsToRoot(t *testing.T) {
	s := NewSampler("")
	if s.diskPath != "/" {
		t.Errorf("expected default diskPath '/', got %q", s.diskPath)
	}
}

func TestParseMeminfoKB(t *testing.T) {
	tests := []struct {
		line string
		want uint64
	}{
		{"MemTotal:       16384000 kB", 16384000},
		{"MemAvailable:   8192000 kB", 8192000},
		{"malformed", 0},
		{"NoValue:", 0},
		{"BadNumber: abc kB", 0},
	}
	for _, tt := range tests {
		if got := parseMeminfoKB(tt.line); got != tt.want {
			t.Errorf("parseMeminfoKB(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
}

func TestDiskPercentUnknownPath(t *testing.T) {
	_, err := diskPercent("/this/path/should/not/exist/sysstats")
	if err == nil {
		t.Error("expected error for missing path")
	}
}

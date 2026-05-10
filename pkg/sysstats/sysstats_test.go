// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC

package sysstats

import (
	"runtime"
	"testing"
)

func TestSamplerSnapshotPopulatesDisk(t *testing.T) {
	s := NewSampler("/")
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if snap.DiskPath != "/" {
		t.Errorf("expected DiskPath '/', got %q", snap.DiskPath)
	}
	if snap.DiskPercent < 0 || snap.DiskPercent > 100 {
		t.Errorf("disk percent out of range: %f", snap.DiskPercent)
	}
	if snap.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestSamplerSnapshotCPUSeedsBaseline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("CPU sampler is Linux-only")
	}

	s := NewSampler("/")
	first, err := s.Snapshot()
	if err != nil {
		t.Fatalf("first Snapshot returned error: %v", err)
	}
	if first.CPUPercent != 0 {
		t.Errorf("expected first CPU sample to be 0, got %f", first.CPUPercent)
	}

	// Second sample should be measurable. Burn a tiny amount of CPU
	// to guarantee /proc/stat moves between reads.
	for i := 0; i < 1_000_000; i++ {
		_ = i * i
	}

	second, err := s.Snapshot()
	if err != nil {
		t.Fatalf("second Snapshot returned error: %v", err)
	}
	if second.CPUPercent < 0 || second.CPUPercent > 100 {
		t.Errorf("second CPU sample out of range: %f", second.CPUPercent)
	}
}

func TestSamplerSnapshotMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("memory sampler is Linux-only")
	}
	s := NewSampler("/")
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if snap.MemoryPercent <= 0 || snap.MemoryPercent > 100 {
		t.Errorf("memory percent out of expected range: %f", snap.MemoryPercent)
	}
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

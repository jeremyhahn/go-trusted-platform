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

//go:build integration

package iso

import (
	"bufio"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// grubMenuScreen is what GRUB draws on a serial terminal, escape sequences
// included, while it counts down to its default entry.
var grubMenuScreen = []string{
	"\x1b[2J\x1b[1;1H                             GNU GRUB  version 2.12",
	"\x1b[4;2H*Alpine Linux (trusted-platform installer)",
	"      Use the ^ and v keys to select which entry is highlighted.",
	"      The highlighted entry will be executed automatically in 5s.",
}

func observeAll(d *grubMenuDetector, lines []string, at time.Time) {
	for _, line := range lines {
		d.Observe(line, at)
	}
}

func TestGRUBMenuDetectorPassesAMenuThatBootsAKernel(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	d := newGRUBMenuDetector(2 * time.Minute)

	observeAll(d, grubMenuScreen, start)
	d.Observe("  Booting `Alpine Linux (trusted-platform installer)'", start.Add(5*time.Second))
	d.Observe("EFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID device path", start.Add(6*time.Second))

	if err := d.Check(start.Add(10 * time.Minute)); err != nil {
		t.Fatalf("a menu followed by a kernel boot must not fail, got %v", err)
	}
}

func TestGRUBMenuDetectorFailsAMenuThatNeverBootsAfterTheGrace(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	d := newGRUBMenuDetector(2 * time.Minute)

	observeAll(d, grubMenuScreen, start)

	if err := d.Check(start.Add(2*time.Minute - time.Second)); err != nil {
		t.Fatalf("a menu inside its grace must not fail yet, got %v", err)
	}

	err := d.Check(start.Add(2 * time.Minute))
	var grubErr ErrGRUBMenuNoBoot
	if !errors.As(err, &grubErr) {
		t.Fatalf("err = %v (%T), want ErrGRUBMenuNoBoot once the grace has passed", err, err)
	}
	if grubErr.Waited != 2*time.Minute {
		t.Errorf("Waited = %s, want 2m0s", grubErr.Waited)
	}
	if len(grubErr.LastLines) != len(grubMenuScreen) {
		t.Fatalf("LastLines = %q, want the %d menu lines", grubErr.LastLines, len(grubMenuScreen))
	}
	if grubErr.LastLines[0] != "GNU GRUB  version 2.12" {
		t.Errorf("LastLines[0] = %q, want the line with its escape sequences stripped", grubErr.LastLines[0])
	}
	if !strings.Contains(err.Error(), "executed automatically in 5s") {
		t.Errorf("error %q does not quote the serial lines", err.Error())
	}
}

func TestGRUBMenuDetectorKeepsWaitingWhileNoMenuIsDrawn(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	d := newGRUBMenuDetector(2 * time.Minute)

	d.Observe("BdsDxe: loading Boot0001 \"UEFI QEMU DVD-ROM QM00003\"", start)
	d.Observe("", start)

	if err := d.Check(start.Add(30 * time.Minute)); err != nil {
		t.Fatalf("firmware output without a GRUB menu must not fail, got %v", err)
	}
}

func TestGRUBMenuDetectorQuotesOnlyTheLastSerialLines(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	d := newGRUBMenuDetector(time.Minute)

	observeAll(d, grubMenuScreen, start)
	for i := 0; i < serialTailLines+5; i++ {
		d.Observe("countdown redraw", start)
	}

	var grubErr ErrGRUBMenuNoBoot
	if !errors.As(d.Check(start.Add(time.Minute)), &grubErr) {
		t.Fatal("a menu past its grace must fail")
	}
	if len(grubErr.LastLines) != serialTailLines {
		t.Errorf("quoted %d lines, want the last %d", len(grubErr.LastLines), serialTailLines)
	}
}

func TestDetectorScanSerialLinesSplitsAtABareCarriageReturn(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("in 5s.\rin 4s.\r\nBooting `Alpine'\nLinux version 6.12"))
	scanner.Split(scanSerialLines)

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	want := []string{"in 5s.", "in 4s.", "", "Booting `Alpine'", "Linux version 6.12"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Errorf("lines = %q, want %q", lines, want)
	}
}

func TestDetectorScanSerialLinesWaitsForMoreDataWithoutATerminator(t *testing.T) {
	advance, token, err := scanSerialLines([]byte("GNU GR"), false)
	if err != nil || advance != 0 || token != nil {
		t.Errorf("scanSerialLines on a partial line = (%d, %q, %v), want (0, nil, nil)", advance, token, err)
	}
}

func TestDetectorRunWatchedKillsTheProcessGroupAtAStuckMenu(t *testing.T) {
	adapter := &CLIAdapter{binaryPath: "/bin/sh"}
	// The child sleep shares the pipe: only a process-group kill lets the
	// call return before the sleep ends.
	script := "printf 'GNU GRUB  version 2.12\\n'; sleep 600; echo never"

	start := time.Now()
	output, err := adapter.runWatched(context.Background(), time.Minute, newGRUBMenuDetector(0), "-c", script)
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("runWatched returned after %s: the stuck menu was not killed promptly", took)
	}

	var grubErr ErrGRUBMenuNoBoot
	if !errors.As(err, &grubErr) {
		t.Fatalf("err = %v (%T), want ErrGRUBMenuNoBoot", err, err)
	}
	if !strings.Contains(string(output), "GNU GRUB") || strings.Contains(string(output), "never") {
		t.Errorf("output = %q, want the menu line and nothing after the kill", output)
	}
}

func TestDetectorRunWatchedReportsTheInstallTimeout(t *testing.T) {
	adapter := &CLIAdapter{binaryPath: "/bin/sh"}

	_, err := adapter.runWatched(context.Background(), 500*time.Millisecond, newGRUBMenuDetector(time.Minute), "-c", "sleep 600")

	var timeoutErr ErrCommandTimeout
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("err = %v (%T), want ErrCommandTimeout", err, err)
	}
	if timeoutErr.Timeout != "500ms" {
		t.Errorf("Timeout = %q, want 500ms", timeoutErr.Timeout)
	}
}

func TestDetectorRunWatchedReturnsTheOutputOfACommandThatExits(t *testing.T) {
	adapter := &CLIAdapter{binaryPath: "/bin/sh"}

	output, err := adapter.runWatched(context.Background(), time.Minute, newGRUBMenuDetector(time.Minute), "-c", "echo installed")
	if err != nil {
		t.Fatalf("runWatched: %v", err)
	}
	if string(output) != "installed\n" {
		t.Errorf("output = %q, want %q", output, "installed\n")
	}
}

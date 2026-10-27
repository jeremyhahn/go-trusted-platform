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

package iso

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// serialTailLines is how many output lines ErrGRUBMenuNoBoot and a
	// failed command's ErrVerbFailed quote: the CLI error plus the guest's
	// last console lines before it powered off.
	serialTailLines = 40
	// serialCheckInterval is how often runWatched asks the detector whether
	// a waiting menu has run out its grace.
	serialCheckInterval = time.Second
	// serialWaitDelay bounds how long runWatched waits for the output pipe
	// to close once the command has exited.
	serialWaitDelay = 10 * time.Second
	// serialMaxLine is the longest serial line the scanner accepts.
	serialMaxLine = 1 << 20
)

// grubMenuMarkers are the text GRUB draws with its menu on a serial terminal.
var grubMenuMarkers = []string{
	"GNU GRUB",
	"Use the ^ and v keys",
	"highlighted entry will be executed automatically",
}

// kernelBootMarkers show the guest left the menu for a kernel: GRUB's own
// "Booting" line for the chosen entry, the EFI stub, or the kernel banner.
var kernelBootMarkers = []string{
	"Booting `",
	"Booting a command list",
	"EFI stub: ",
	"Linux version ",
}

// ansiEscape matches the terminal control sequences GRUB draws its menu with.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// grubMenuDetector recognises a guest stopped at the GRUB menu: the menu is
// drawn on the serial console and no kernel boot line follows within grace.
// It reads no clock of its own; its caller passes the time with every call,
// from one goroutine.
type grubMenuDetector struct {
	grace time.Duration
	// menuSeenAt is when the menu waiting for a boot line appeared; zero
	// while no menu is waiting. A menu drawn again after a boot re-arms it.
	menuSeenAt time.Time
	tail       []string
}

func newGRUBMenuDetector(grace time.Duration) *grubMenuDetector {
	return &grubMenuDetector{grace: grace}
}

// Observe takes one serial line received at now.
func (d *grubMenuDetector) Observe(line string, now time.Time) {
	line = strings.TrimSpace(ansiEscape.ReplaceAllString(line, ""))
	if line == "" {
		return
	}
	d.tail = append(d.tail, line)
	if len(d.tail) > serialTailLines {
		d.tail = d.tail[len(d.tail)-serialTailLines:]
	}
	switch {
	case containsAny(line, kernelBootMarkers):
		d.menuSeenAt = time.Time{}
	case d.menuSeenAt.IsZero() && containsAny(line, grubMenuMarkers):
		d.menuSeenAt = now
	}
}

// Check returns ErrGRUBMenuNoBoot once a menu has waited grace or longer
// for a kernel boot line at now, and nil otherwise.
func (d *grubMenuDetector) Check(now time.Time) error {
	if d.menuSeenAt.IsZero() {
		return nil
	}
	waited := now.Sub(d.menuSeenAt)
	if waited < d.grace {
		return nil
	}
	return ErrGRUBMenuNoBoot{
		Waited:    waited,
		LastLines: append([]string(nil), d.tail...),
	}
}

func containsAny(line string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

// scanSerialLines splits serial output at "\n" or "\r": GRUB redraws its
// countdown with bare carriage returns.
func scanSerialLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// runWatched runs platformctl like runCommandWithTimeout, but reads its
// combined output as it arrives and feeds every line to detector. A command
// that boots a guest with SerialConsole set (`iso test install`) writes the
// guest's serial console to its own stdout (pkg/qemu: -serial stdio). When the
// detector reports a guest stuck at the GRUB menu, the command's whole process
// group, QEMU included, is killed and the detector's error returned instead of
// waiting out timeout.
func (c *CLIAdapter) runWatched(ctx context.Context, timeout time.Duration, detector *grubMenuDetector, args ...string) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reader, writer := io.Pipe()
	cmd := exec.CommandContext(runCtx, c.binaryPath, args...)
	cmd.Stdout = writer
	cmd.Stderr = writer
	killGroupOnCancel(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	waitDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		writer.Close()
		waitDone <- err
	}()

	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), serialMaxLine)
		scanner.Split(scanSerialLines)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		// A line past serialMaxLine stops the scanner; keep draining so the
		// command never blocks on a full pipe.
		if _, err := io.Copy(io.Discard, reader); err != nil {
			reader.CloseWithError(err)
		}
	}()

	var output bytes.Buffer
	var watchErr error
	ticker := time.NewTicker(serialCheckInterval)
	defer ticker.Stop()
	for lines != nil {
		select {
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if line != "" {
				output.WriteString(line)
				output.WriteByte('\n')
			}
			detector.Observe(line, time.Now())
		case now := <-ticker.C:
			if watchErr == nil {
				if watchErr = detector.Check(now); watchErr != nil {
					cancel()
				}
			}
		}
	}

	err := <-waitDone
	if watchErr != nil {
		return output.Bytes(), watchErr
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return output.Bytes(), ErrCommandTimeout{Command: strings.Join(args, " "), Timeout: timeout.String()}
	}
	if err != nil {
		// The command prints its error last: quoting the tail names the
		// cause instead of only the exit status, bounded to serialTailLines.
		return output.Bytes(), ErrVerbFailed{Stderr: strings.Join(detector.tail, "\n"), Err: err}
	}
	return output.Bytes(), nil
}

// killGroupOnCancel makes cancelling cmd's context kill its whole process
// group, not only platformctl: a QEMU grandchild would otherwise keep the
// output pipe open and block Wait past the test's deadline. WaitDelay bounds
// the wait for the pipe once the group is killed.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = serialWaitDelay
}

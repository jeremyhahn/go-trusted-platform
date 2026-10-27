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

// The process runner every CLIAdapter verb goes through, and the errors it
// returns. It carries no build tag, with grub_detector.go, so its tests run
// in `make test`; the verbs themselves stay in the integration-tagged
// cli_adapter.go.

package iso

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CLIAdapter implements ISOCommands using platformctl CLI commands.
type CLIAdapter struct {
	binaryPath string
}

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
	killGroupOnCancel(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("command failed: %s: %w", string(output), err)
	}
	return output, nil
}

// runCommandWithTimeout runs a command with a specific timeout.
func (c *CLIAdapter) runCommandWithTimeout(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := c.runCommand(timeoutCtx, args...)
	if err != nil && errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
		return output, ErrCommandTimeout{Command: strings.Join(args, " "), Timeout: timeout.String()}
	}
	return output, err
}

// ErrCommandTimeout indicates a command timed out.
type ErrCommandTimeout struct {
	Command string
	Timeout string
}

func (e ErrCommandTimeout) Error() string {
	return fmt.Sprintf("command %s timed out after %s", e.Command, e.Timeout)
}

// ErrGRUBMenuNoBoot is returned when a guest draws the GRUB menu on its serial
// console and no kernel boot line follows within grubMenuGrace: the guest is
// stuck at the menu, and waiting out the install timeout would only spend time.
type ErrGRUBMenuNoBoot struct {
	Waited    time.Duration
	LastLines []string
}

func (e ErrGRUBMenuNoBoot) Error() string {
	return fmt.Sprintf("guest stopped at the GRUB menu: no kernel boot line on the serial console %s after the menu appeared; last serial lines:\n%s",
		e.Waited, strings.Join(e.LastLines, "\n"))
}

// ErrVerbFailed reports a platformctl verb that exited non-zero or printed no
// result, with the stderr it wrote.
type ErrVerbFailed struct {
	Stderr string
	Err    error
}

func (e ErrVerbFailed) Error() string {
	if e.Err == nil {
		return e.Stderr
	}
	return e.Err.Error() + ": " + e.Stderr
}

// Unwrap returns the process error.
func (e ErrVerbFailed) Unwrap() error { return e.Err }

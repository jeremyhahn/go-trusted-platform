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

// Package boundedexec runs the integration suites' external commands under a
// per-command deadline, so a wedged ovs-vsctl or ovs-ofctl fails its own call
// with the command line, the elapsed time and its stderr instead of hanging
// until the package's go test -timeout panics (CA m639).
//
// Cmd mirrors the os/exec calls the suites already make (Command,
// CommandContext, Run, Output, CombinedOutput), so a call site changes only the
// package it builds the command from. The package carries no build tag so its
// own tests run in the unit suite with a stand-in binary on PATH.
package boundedexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Deadline bounds every command this package runs. No ovs-vsctl or ovs-ofctl
// call a suite makes needs more than a few seconds against a live OVS.
const Deadline = 30 * time.Second

// waitDelay bounds how long Wait keeps reading the pipes after the process is
// killed, so a child that inherited them cannot hold the call open.
const waitDelay = 2 * time.Second

// vsctlName is the one command with its own timeout flag: ovs-vsctl waits
// forever for ovsdb-server unless told otherwise, so it gets --timeout as well
// as the process deadline.
const vsctlName = "ovs-vsctl"

// TimeoutError reports a command that did not exit within its deadline and
// was killed.
type TimeoutError struct {
	// Command is the full command line that was run.
	Command string
	// Deadline is the deadline the command was given.
	Deadline time.Duration
	// Elapsed is how long the command ran before it was killed.
	Elapsed time.Duration
	// Stderr is whatever the command wrote to stderr before it was killed.
	Stderr string
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("%s: no exit within the %s deadline, killed after %s; stderr: %q",
		e.Command, e.Deadline, e.Elapsed.Round(time.Millisecond), e.Stderr)
}

// CommandError reports a command that exited with an error, or could not be
// started, within its deadline.
type CommandError struct {
	// Command is the full command line that was run.
	Command string
	// Elapsed is how long the command ran.
	Elapsed time.Duration
	// Stderr is what the command wrote to stderr.
	Stderr string
	// Err is the os/exec error; an *exec.ExitError carries the exit code.
	Err error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("%s: %v after %s; stderr: %q",
		e.Command, e.Err, e.Elapsed.Round(time.Millisecond), e.Stderr)
}

// Unwrap exposes the os/exec error to errors.Is and errors.As.
func (e *CommandError) Unwrap() error { return e.Err }

// Cmd is a command that runs under a deadline. Build one with Command or
// CommandContext.
type Cmd struct {
	ctx      context.Context
	deadline time.Duration
	name     string
	args     []string
}

// Command returns a Cmd that runs name with args under Deadline.
func Command(name string, args ...string) *Cmd {
	return CommandContext(context.Background(), name, args...)
}

// CommandContext returns a Cmd that runs name with args under Deadline, or
// until ctx ends, whichever comes first.
func CommandContext(ctx context.Context, name string, args ...string) *Cmd {
	return &Cmd{ctx: ctx, deadline: Deadline, name: name, args: args}
}

// WithDeadline replaces the command's deadline and returns the command.
func (c *Cmd) WithDeadline(deadline time.Duration) *Cmd {
	c.deadline = deadline
	return c
}

// String returns the command line as it is run, including the --timeout flag
// added to ovs-vsctl.
func (c *Cmd) String() string {
	return strings.Join(append([]string{c.name}, c.argv()...), " ")
}

// Run runs the command and returns its error.
func (c *Cmd) Run() error {
	_, err := c.run(false)
	return err
}

// Output runs the command and returns its stdout.
func (c *Cmd) Output() ([]byte, error) {
	return c.run(false)
}

// CombinedOutput runs the command and returns its stdout and stderr together.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	return c.run(true)
}

// argv returns the arguments the command is run with: ovs-vsctl gets a
// --timeout of the deadline rounded up to whole seconds (never 0, which
// ovs-vsctl reads as "wait forever"), unless the caller passed one.
func (c *Cmd) argv() []string {
	if c.name != vsctlName {
		return c.args
	}
	for _, arg := range c.args {
		if strings.HasPrefix(arg, "--timeout") {
			return c.args
		}
	}
	seconds := int(math.Max(1, math.Ceil(c.deadline.Seconds())))
	return append([]string{fmt.Sprintf("--timeout=%d", seconds)}, c.args...)
}

// run starts the command under the deadline and waits for it. With combined
// set, the returned bytes are stdout and stderr together; otherwise stdout.
// stderr is always captured on its own for the error.
func (c *Cmd) run(combined bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(c.ctx, c.deadline)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.name, c.argv()...)
	cmd.WaitDelay = waitDelay

	out := &syncBuffer{}
	var stderr bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = &stderr
	if combined {
		cmd.Stderr = io.MultiWriter(out, &stderr)
	}

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)
	if err == nil {
		return out.Bytes(), nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && c.ctx.Err() == nil {
		return out.Bytes(), &TimeoutError{
			Command:  c.String(),
			Deadline: c.deadline,
			Elapsed:  elapsed,
			Stderr:   stderr.String(),
		}
	}
	return out.Bytes(), &CommandError{
		Command: c.String(),
		Elapsed: elapsed,
		Stderr:  stderr.String(),
		Err:     err,
	}
}

// syncBuffer is a bytes.Buffer safe for the two goroutines os/exec copies
// stdout and stderr with when they go to different writers that share it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Bytes()
}

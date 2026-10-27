package iso

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type commandResult struct {
	output []byte
	err    error
}

// TestRunCommandWithTimeout_KillsTheProcessGroup pins the fixture runner
// against the TestBoot hang: a child that holds the output pipe open past the
// timeout (QEMU under platformctl) must not keep the runner waiting. The runner
// returns the output collected so far with ErrCommandTimeout.
func TestRunCommandWithTimeout_KillsTheProcessGroup(t *testing.T) {
	adapter := &CLIAdapter{binaryPath: "/bin/sh"}
	timeout := time.Minute

	// The shell writes its output, then opens the FIFO: the test reads
	// "ready" only once "partial" is in the pipe. Expiring the parent then,
	// not on a wall clock, keeps a slow shell start from emptying the output.
	ready := filepath.Join(t.TempDir(), "ready")
	require.NoError(t, syscall.Mkfifo(ready, 0o600))
	readyRead := make(chan error, 1)
	go func() {
		line, err := os.ReadFile(ready)
		if err == nil && string(line) != "ready\n" {
			err = errors.New("unexpected readiness line: " + string(line))
		}
		readyRead <- err
	}()

	parent := newExpiringContext()
	done := make(chan commandResult, 1)
	go func() {
		output, err := adapter.runCommandWithTimeout(parent, timeout,
			"-c", `echo partial; echo ready > "$1"; sleep 60 & wait`, "sh", ready)
		done <- commandResult{output: output, err: err}
	}()

	readyBound := time.NewTimer(timeout)
	defer readyBound.Stop()
	select {
	case err := <-readyRead:
		require.NoError(t, err)
	case <-readyBound.C:
		t.Fatalf("the shell did not signal readiness within %v", timeout)
	}
	parent.expire()

	bound := time.NewTimer(serialWaitDelay)
	defer bound.Stop()
	select {
	case result := <-done:
		var timeoutErr ErrCommandTimeout
		require.True(t, errors.As(result.err, &timeoutErr), "got %v", result.err)
		assert.Equal(t, timeout.String(), timeoutErr.Timeout)
		assert.Equal(t, "partial\n", string(result.output))
	case <-bound.C:
		t.Fatalf("the runner was still waiting %v after its deadline expired", serialWaitDelay)
	}
}

// expiringContext is a parent context whose deadline the test expires: its
// Err reports context.DeadlineExceeded, as a parent deadline would.
type expiringContext struct {
	context.Context
	done chan struct{}
}

func newExpiringContext() *expiringContext {
	return &expiringContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *expiringContext) expire() { close(c.done) }

func (c *expiringContext) Done() <-chan struct{} { return c.done }

func (c *expiringContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestRunCommandWithTimeout_ReturnsTheCommandError(t *testing.T) {
	adapter := &CLIAdapter{binaryPath: "/bin/sh"}

	output, err := adapter.runCommandWithTimeout(context.Background(), time.Minute, "-c", "echo failed; exit 3")

	require.Error(t, err)
	var timeoutErr ErrCommandTimeout
	assert.False(t, errors.As(err, &timeoutErr))
	assert.Equal(t, "failed\n", string(output))
}

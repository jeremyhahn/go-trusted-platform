//go:build integration

package iso

import (
	"context"
	"errors"
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
	timeout := 200 * time.Millisecond

	done := make(chan commandResult, 1)
	go func() {
		output, err := adapter.runCommandWithTimeout(context.Background(), timeout,
			"-c", "echo partial; sleep 60 & wait")
		done <- commandResult{output: output, err: err}
	}()

	bound := time.NewTimer(timeout + serialWaitDelay)
	defer bound.Stop()
	select {
	case result := <-done:
		var timeoutErr ErrCommandTimeout
		require.True(t, errors.As(result.err, &timeoutErr), "got %v", result.err)
		assert.Equal(t, timeout.String(), timeoutErr.Timeout)
		assert.Equal(t, "partial\n", string(result.output))
	case <-bound.C:
		t.Fatalf("the runner was still waiting %v after its %v timeout", serialWaitDelay, timeout)
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

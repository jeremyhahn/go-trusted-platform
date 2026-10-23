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

package testenv

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitUntil_ConditionAlreadyTrue(t *testing.T) {
	var calls atomic.Int32
	err := WaitUntil(context.Background(), time.Second, "ready", func() bool {
		calls.Add(1)
		return true
	})

	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "a met condition is checked once, without waiting a tick")
}

func TestWaitUntil_ConditionBecomesTrue(t *testing.T) {
	var calls atomic.Int32
	err := WaitUntil(context.Background(), 5*time.Second, "third check", func() bool {
		return calls.Add(1) >= 3
	})

	require.NoError(t, err)
	assert.Equal(t, int32(3), calls.Load(), "polling stops at the first check that holds")
}

func TestWaitUntil_DeadlineNamesCondition(t *testing.T) {
	err := WaitUntil(context.Background(), 50*time.Millisecond, "bridge br-test up", func() bool {
		return false
	})

	var waitErr *WaitTimeoutError
	require.ErrorAs(t, err, &waitErr)
	assert.Equal(t, "bridge br-test up", waitErr.Condition)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "bridge br-test up")
}

func TestWaitUntil_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := WaitUntil(ctx, time.Minute, "never", func() bool { return false })

	var waitErr *WaitTimeoutError
	require.ErrorAs(t, err, &waitErr)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, errors.Is(err, context.DeadlineExceeded), "a cancelled wait is not reported as a timeout")
}

func TestWaitUntilEvery_UsesInterval(t *testing.T) {
	var calls atomic.Int32
	start := time.Now()
	err := WaitUntilEvery(context.Background(), 5*time.Second, 10*time.Millisecond, "second check", func() bool {
		return calls.Add(1) >= 2
	})

	require.NoError(t, err)
	assert.Less(t, time.Since(start), WaitInterval, "the second check comes after the given interval, not WaitInterval")
}

func TestWaitUntilEvery_DeadlineNamesCondition(t *testing.T) {
	err := WaitUntilEvery(context.Background(), 30*time.Millisecond, 10*time.Millisecond, "DNS answering", func() bool {
		return false
	})

	var waitErr *WaitTimeoutError
	require.ErrorAs(t, err, &waitErr)
	assert.Equal(t, "DNS answering", waitErr.Condition)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestWaitFor_ReturnsWaitResult(t *testing.T) {
	exitErr := errors.New("exit status 1")

	require.NoError(t, WaitFor(context.Background(), time.Second, "process exit", func() error { return nil }))
	assert.ErrorIs(t, WaitFor(context.Background(), time.Second, "process exit", func() error { return exitErr }), exitErr)
}

func TestWaitFor_DeadlineNamesCondition(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	err := WaitFor(context.Background(), 20*time.Millisecond, "QEMU process exit", func() error {
		<-release
		return nil
	})

	var waitErr *WaitTimeoutError
	require.ErrorAs(t, err, &waitErr)
	assert.Equal(t, "QEMU process exit", waitErr.Condition)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestElapse_Elapses(t *testing.T) {
	start := time.Now()
	require.NoError(t, Elapse(context.Background(), 20*time.Millisecond))
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
}

func TestElapse_ContextEndsFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Elapse(ctx, time.Minute)

	var waitErr *WaitTimeoutError
	require.ErrorAs(t, err, &waitErr)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, "1m0s to elapse", waitErr.Condition)
}

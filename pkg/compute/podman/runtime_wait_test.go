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

package podman

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeContainerRunning replaces the OCI state seam: the container reports
// running for the first runningPolls reads and stopped after that; a negative
// runningPolls never stops. Each read is sent on the returned channel.
func fakeContainerRunning(t *testing.T, runningPolls int64) <-chan struct{} {
	t.Helper()

	polled := make(chan struct{}, 64)
	var reads atomic.Int64
	restore := containerRunning
	containerRunning = func(*Runtime, context.Context, string) bool {
		n := reads.Add(1)
		select {
		case polled <- struct{}{}:
		default:
		}
		return runningPolls < 0 || n <= runningPolls
	}
	t.Cleanup(func() { containerRunning = restore })
	return polled
}

func TestRuntimeWaitContainer_ReturnsWhenContainerExits(t *testing.T) {
	fakeContainerRunning(t, 2)
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "wait-exit")

	_, err := rt.WaitContainer(context.Background(), id)
	require.NoError(t, err)

	state, err := rt.lookupContainer(id)
	require.NoError(t, err)
	assert.Equal(t, ContainerStateExited, state.State)
}

func TestRuntimeWaitContainer_CancelInterruptsWait(t *testing.T) {
	polled := fakeContainerRunning(t, -1)
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "wait-cancel")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := rt.WaitContainer(ctx, id)
		done <- err
	}()

	// Cancel once the wait is underway: it must return without the
	// container ever exiting.
	<-polled
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestRuntimeWaitContainer_UnknownContainer(t *testing.T) {
	rt := newTestRuntime(t)

	_, err := rt.WaitContainer(context.Background(), "missing")
	require.ErrorIs(t, err, ErrContainerNotFound)
}

func TestRuntimeStopContainer_GracefulExitMarksStopped(t *testing.T) {
	fakeContainerRunning(t, 1)
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "stop-graceful")

	require.NoError(t, rt.StopContainer(context.Background(), id, 30))

	state, err := rt.lookupContainer(id)
	require.NoError(t, err)
	assert.Equal(t, ContainerStateStopped, state.State)
	assert.NotNil(t, state.FinishedAt)
}

func TestRuntimeStopContainer_CancelEndsGracePeriod(t *testing.T) {
	fakeContainerRunning(t, -1)
	rt := newTestRuntime(t)
	id := createTestContainer(t, rt, "stop-cancel")

	// A container that never exits and a context already cancelled: the
	// grace period must not be waited out, and the container is still
	// recorded as stopped after the forced kill.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, rt.StopContainer(ctx, id, 3600))

	state, err := rt.lookupContainer(id)
	require.NoError(t, err)
	assert.Equal(t, ContainerStateStopped, state.State)
}

func TestRuntimeStopContainer_UnknownContainer(t *testing.T) {
	rt := newTestRuntime(t)

	err := rt.StopContainer(context.Background(), "missing", 1)
	require.ErrorIs(t, err, ErrContainerNotFound)
}

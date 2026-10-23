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

package vtpm_test

import (
	"context"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pkg/swtpm unit tests replace the swtpm binaries with a fake. These
// tests drive the real swtpm and swtpm_setup from the devcontainer, so a
// missing binary fails them.

// initializedSWTPM returns an swtpm whose state the real swtpm_setup created.
func initializedSWTPM(t *testing.T, ctx context.Context, pcrBanks ...string) *swtpm.SWTPM {
	t.Helper()

	sw, err := swtpm.NewSWTPM(&swtpm.Config{StateDir: t.TempDir(), PCRBanks: pcrBanks}, nil)
	require.NoError(t, err, "swtpm and swtpm_setup must be installed")
	require.False(t, sw.IsInitialized())
	require.NoError(t, sw.Initialize(ctx))
	require.True(t, sw.IsInitialized())
	return sw
}

// startedSWTPM returns a running swtpm that is stopped when the test ends.
func startedSWTPM(t *testing.T, ctx context.Context) *swtpm.SWTPM {
	t.Helper()

	sw := initializedSWTPM(t, ctx)
	require.NoError(t, sw.Start(ctx))
	t.Cleanup(func() {
		if sw.IsRunning() {
			if err := sw.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}
	})
	return sw
}

// killSWTPM kills the swtpm process behind the SWTPM's back and waits for
// the SWTPM to observe the exit.
func killSWTPM(t *testing.T, sw *swtpm.SWTPM) {
	t.Helper()

	require.NoError(t, syscall.Kill(sw.PID(), syscall.SIGKILL))
	require.Eventually(t, func() bool { return !sw.IsRunning() }, 5*time.Second, 20*time.Millisecond)
}

func TestSWTPMDaemon_InitializeMultiplePCRBanks(t *testing.T) {
	initializedSWTPM(t, context.Background(), "sha256", "sha384", "sha512")
}

func TestSWTPMDaemon_InitializeCancelledContext(t *testing.T) {
	sw, err := swtpm.NewSWTPM(&swtpm.Config{StateDir: t.TempDir()}, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.ErrorIs(t, sw.Initialize(ctx), swtpm.ErrInitFailed)
}

func TestSWTPMDaemon_StartStop(t *testing.T) {
	ctx := context.Background()
	sw := initializedSWTPM(t, ctx)

	require.NoError(t, sw.Start(ctx))
	assert.True(t, sw.IsRunning())
	assert.Greater(t, sw.PID(), 0)

	require.NoError(t, sw.WaitForSocket(5*time.Second))
	_, err := os.Stat(sw.SocketPath())
	require.NoError(t, err)

	require.NoError(t, sw.Stop())
	assert.False(t, sw.IsRunning())
	assert.Equal(t, 0, sw.PID())
}

func TestSWTPMDaemon_StartAlreadyRunning(t *testing.T) {
	ctx := context.Background()
	sw := startedSWTPM(t, ctx)

	assert.ErrorIs(t, sw.Start(ctx), swtpm.ErrAlreadyRunning)
}

func TestSWTPMDaemon_SendStartup(t *testing.T) {
	ctx := context.Background()
	sw := startedSWTPM(t, ctx)
	require.NoError(t, sw.WaitForSocket(5*time.Second))

	require.NoError(t, sw.SendStartup())
	// A second TPM2_Startup reports TPM_RC_INITIALIZE, which is not an error.
	require.NoError(t, sw.SendStartup())
}

func TestSWTPMDaemon_ConcurrentAccess(t *testing.T) {
	sw := startedSWTPM(t, context.Background())

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.True(t, sw.IsRunning())
			assert.NotEmpty(t, sw.StateDir())
			assert.NotEmpty(t, sw.SocketPath())
			assert.Greater(t, sw.PID(), 0)
		}()
	}
	wg.Wait()
}

func TestSWTPMDaemon_KilledProcess(t *testing.T) {
	sw := startedSWTPM(t, context.Background())

	killSWTPM(t, sw)

	assert.ErrorIs(t, sw.WaitForSocket(2*time.Second), swtpm.ErrSocketNotReady)
	assert.NoError(t, sw.Stop(), "Stop must tolerate a process that already exited")
}

func TestSWTPMDaemon_StopExisting(t *testing.T) {
	sw := startedSWTPM(t, context.Background())
	require.NoError(t, sw.WaitForSocket(5*time.Second))

	require.NoError(t, swtpm.StopExisting(sw.StateDir()))

	require.Eventually(t, func() bool { return !sw.IsRunning() }, 5*time.Second, 20*time.Millisecond)
}

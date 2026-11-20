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

//go:build linux

package process

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
)

func TestSupervisor_OnChildExitRunsForACrashDuringReadiness(t *testing.T) {
	// The launch claim stays held through readiness. A child that dies
	// while its own launch still holds the claim is not a replacement's
	// predecessor: its cleanup is owed, and nothing else would run it.
	supervisor, launcher, rec := newHookedSupervisor(t, 0, nil)
	ctx := testContext(t)
	// The gate is never opened: the child dies before it would listen,
	// and its relaunch owns the socket path by then.
	_ = launcher.deferNextListen()

	started := make(chan error, 1)
	go func() { started <- supervisor.StartService(ctx, gateway.ServiceVPNWireGuard) }()
	// launchCount records the launch before the child exists (#742), so
	// wait for the child itself: lastChild right after the count can find
	// none on a loaded runner under -race.
	var child *fakeChild
	require.Eventually(t, func() bool {
		children := launcher.allChildren()
		if len(children) != 1 {
			return false
		}
		child = children[0]
		return true
	}, 5*time.Second, time.Millisecond, "the wireguard child is launched")
	supervisor.mu.Lock()
	launching := supervisor.processes[WireGuardProcess].launching
	supervisor.mu.Unlock()
	require.True(t, launching, "the child is still waiting for readiness")

	child.exit(errors.New("signal: killed"))
	require.Eventually(t, func() bool { return rec.callCount() == 1 },
		5*time.Second, time.Millisecond, "the crash during readiness runs the exit hook")
	assert.Never(t, func() bool { return rec.callCount() > 1 },
		200*time.Millisecond, 10*time.Millisecond, "the hook runs once for that exit")
	<-started
}

func TestSupervisor_StartServiceReplacementReplaysTheVPNFollower(t *testing.T) {
	// A StartService that replaces a crashed wireguard child during its
	// backoff leaves the old restart loop with a live child, so that loop
	// replays nothing: the replacement's own success path must relaunch
	// the vpn follower, whose leases went with the crashed hub.
	const backoff = 7 * time.Second
	supervisor, launcher, clock := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = backoff
		c.RestartBudget = 10
	})
	ctx := testContext(t)
	startDatapath(t, ctx, supervisor, launcher, "v1")
	wgChild := startWireGuard(t, ctx, supervisor, launcher)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceManagementVPN))
	vpnChild := launcher.lastChild()

	held := clock.holdDelay(backoff)
	wgChild.exit(errors.New("signal: killed"))
	held.awaitEntered(t, ctx)

	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceVPNWireGuard), "a replacement starts during the backoff")
	awaitRelaunch(t, supervisor, launcher, "vpn", 5)
	assert.Contains(t, vpnChild.signalled(), os.Signal(syscall.SIGTERM),
		"the vpn child whose peers went with the crashed hub is stopped")
	require.NoError(t, supervisor.ServiceHealth(gateway.ServiceManagementVPN))

	close(held.release)
	assert.Never(t, func() bool { return launcher.launchCount() != 5 },
		300*time.Millisecond, 10*time.Millisecond, "the backoff tick relaunches nothing over the replacement")
}

// blockingExitHook returns an OnChildExit hook whose first call closes
// entered and waits for release; later calls return at once. release is
// closed at the test's end if the test has not closed it.
func blockingExitHook(t *testing.T) (hook func(context.Context, Definition) error, entered <-chan struct{}, release func()) {
	t.Helper()
	enteredCh := make(chan struct{})
	releaseCh := make(chan struct{})
	var first, releaseOnce sync.Once
	release = func() { releaseOnce.Do(func() { close(releaseCh) }) }
	hook = func(context.Context, Definition) error {
		blocked := false
		first.Do(func() { blocked = true; close(enteredCh) })
		if blocked {
			<-releaseCh
		}
		return nil
	}
	return hook, enteredCh, release
}

func TestSupervisor_ACrashIsRecordedBeforeItsExitHookRuns(t *testing.T) {
	// The crash is recorded with the child cleared, so a StartService that
	// claims before the exit hook or the restart bookkeeping sees a
	// replacement and replays the followers.
	hook, entered, release := blockingExitHook(t)
	supervisor, launcher, _ := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = 7 * time.Second
		c.RestartBudget = 10
		c.OnChildExit = hook
	})
	t.Cleanup(release)
	ctx := testContext(t)
	startDatapath(t, ctx, supervisor, launcher, "v1")
	wgChild := startWireGuard(t, ctx, supervisor, launcher)

	wgChild.exit(errors.New("signal: killed"))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the exit hook never ran")
	}
	supervisor.mu.Lock()
	failure := supervisor.processes[WireGuardProcess].failure
	supervisor.mu.Unlock()
	require.Error(t, failure, "the crash is recorded while its exit hook runs")
	var exited *ErrProcessExited
	assert.ErrorAs(t, failure, &exited)
	release()
}

func TestSupervisor_AReplacementClaimedAfterTheExitHookReplaysTheVPNFollower(t *testing.T) {
	// A StartService waiting on the exit hook claims the moment cleanup
	// completes, before the old restart loop records the crash. The claim
	// must still see a replacement and replay the vpn follower, and the old
	// loop's bookkeeping must not mark the running replacement down.
	const backoff = 7 * time.Second
	hook, entered, release := blockingExitHook(t)
	supervisor, launcher, clock := newSupervisor(t, func(c *Config) {
		c.RestartBackoff = backoff
		c.RestartBudget = 10
		c.OnChildExit = hook
	})
	t.Cleanup(release)
	ctx := testContext(t)
	held := clock.holdDelay(backoff)
	startDatapath(t, ctx, supervisor, launcher, "v1")
	wgChild := startWireGuard(t, ctx, supervisor, launcher)
	require.NoError(t, supervisor.StartService(ctx, gateway.ServiceManagementVPN))
	vpnChild := launcher.lastChild()

	wgChild.exit(errors.New("signal: killed"))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the exit hook never ran")
	}
	started := make(chan error, 1)
	go func() { started <- supervisor.StartService(ctx, gateway.ServiceVPNWireGuard) }()
	// Let the StartService reach its wait on the cleanup, so it races the
	// old loop for the lock the moment the hook returns.
	time.Sleep(100 * time.Millisecond)
	release()

	select {
	case err := <-started:
		require.NoError(t, err, "the replacement claimed after the cleanup starts")
	case <-time.After(10 * time.Second):
		t.Fatal("the replacement StartService never returned")
	}
	awaitRelaunch(t, supervisor, launcher, "vpn", 5)
	assert.Contains(t, vpnChild.signalled(), os.Signal(syscall.SIGTERM),
		"the vpn child whose peers went with the crashed hub is stopped")
	require.NoError(t, supervisor.ServiceHealth(gateway.ServiceManagementVPN))
	assert.Never(t, func() bool { return supervisor.ServiceHealth(gateway.ServiceVPNWireGuard) != nil },
		300*time.Millisecond, 10*time.Millisecond, "the old loop's bookkeeping leaves the running replacement up")

	close(held.release)
	assert.Never(t, func() bool { return launcher.launchCount() != 5 },
		300*time.Millisecond, 10*time.Millisecond, "the old loop relaunches nothing over the replacement")
}

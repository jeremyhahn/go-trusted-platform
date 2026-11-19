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
	"errors"
	"os"
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
	require.Eventually(t, func() bool { return launcher.launchCount() == 1 },
		5*time.Second, time.Millisecond, "the wireguard child is launched")
	supervisor.mu.Lock()
	launching := supervisor.processes[WireGuardProcess].launching
	supervisor.mu.Unlock()
	require.True(t, launching, "the child is still waiting for readiness")

	launcher.lastChild().exit(errors.New("signal: killed"))
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

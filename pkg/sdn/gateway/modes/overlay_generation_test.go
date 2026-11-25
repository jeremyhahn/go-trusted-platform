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

package modes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cookies of flows other owners keep on the bridge the overlay shares: a
// firewall generation and the pipeline's.
const (
	foreignFirewallCookie uint64 = 0xF1BE000100000007
	foreignPipelineCookie uint64 = 0xF1BE000000000003
)

// relaunch is an overlay a killed predecessor left its flows to, and the
// relaunched overlay started over them.
type relaunch struct {
	old  *OverlayModeHandler
	next *overlayFixture
	// oldFlows is the switch as the predecessor left it; mark is the batch
	// count before the relaunched overlay started.
	oldFlows []string
	mark     int
	// decapB is the predecessor's decap authorisation of VTEP B.
	decapB string
}

// newRelaunch runs a predecessor with the test VNI and remote VTEP B, which
// shares the bridge with a firewall and the pipeline, kills it, and starts a
// new overlay on the switch it left, with the test VNI and no remote VTEP
// learned yet.
func newRelaunch(t *testing.T) *relaunch {
	t.Helper()
	return relaunchOver(t, false)
}

// newUpgrade is newRelaunch over a predecessor from the release before flow
// generations, whose overlay flows all carry legacyOverlayCookie.
func newUpgrade(t *testing.T) *relaunch {
	t.Helper()
	return relaunchOver(t, true)
}

// asLegacy returns the batch as the release before flow generations sent
// it: every overlay flow under the exact legacyOverlayCookie.
func asLegacy(batch []*openflow.FlowMod) []*openflow.FlowMod {
	out := make([]*openflow.FlowMod, 0, len(batch))
	for _, mod := range batch {
		if mod.Cookie&ovs.OwnerCookieMask == OverlayCookie {
			legacy := *mod
			legacy.Cookie = legacyOverlayCookie
			if legacy.CookieMask != 0 {
				legacy.CookieMask = ^uint64(0)
			}
			mod = &legacy
		}
		out = append(out, mod)
	}
	return out
}

func relaunchOver(t *testing.T, legacy bool) *relaunch {
	t.Helper()
	ctx := context.Background()
	old := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, old.route(t, imet(ovlL2VNI, ovlVTEPB)))
	require.NoError(t, old.sw.SendFlowMods(ctx, []*openflow.FlowMod{
		foreignFlow(foreignFirewallCookie, TableCTGate),
		foreignFlow(foreignPipelineCookie, TableIngress),
	}))

	// SIGKILL runs no Stop: the switch keeps every flow the run installed.
	sw := newFakeSwitch()
	for _, batch := range old.sw.batchesSince(0) {
		if legacy {
			batch = asLegacy(batch)
		}
		require.NoError(t, sw.SendFlowMods(ctx, batch))
	}
	r := &relaunch{old: old.handler, oldFlows: sw.table(), mark: sw.batchCount()}
	decap := sw.matching("t=10 ", "10.0.0.2")
	require.Len(t, decap, 1, "precondition: the predecessor authorised VTEP B's decap")
	r.decapB = decap[0]

	next := &overlayFixture{ovs: newFakeOverlayOVS(), sw: sw, speaker: newFakeSpeaker()}
	h, err := NewOverlayModeHandler(overlayConfig(next.speaker), next.ovs, sw)
	require.NoError(t, err)
	next.handler = h
	r.next = next.start(t).withVNI(t)
	return r
}

// foreignFlow is a flow another owner installed, on a port the overlay does
// not use.
func foreignFlow(cookie uint64, table uint8) *openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.Command = openflow.OFPFCAdd
	f.Cookie = cookie
	f.TableID = table
	f.Priority = 1
	f.Match.AddInPort(99)
	return f
}

// sweepDue is when the relaunched overlay sweeps its predecessor's flows.
func (r *relaunch) sweepDue() time.Time {
	r.next.handler.mu.Lock()
	defer r.next.handler.mu.Unlock()
	return r.next.handler.staleSweepAt
}

func TestOverlayRelaunchKeepsForwarding(t *testing.T) {
	r := newRelaunch(t)
	oldCookie, newCookie := r.old.cookie, r.next.handler.cookie

	t.Run("draws a new generation under the overlay's owner", func(t *testing.T) {
		assert.NotEqual(t, oldCookie, newCookie)
		assert.Equal(t, OverlayCookie, newCookie&ovs.OwnerCookieMask)
		assert.Equal(t, OverlayCookie, oldCookie&ovs.OwnerCookieMask)
	})

	t.Run("deletes nothing while it installs", func(t *testing.T) {
		for _, batch := range r.next.sw.batchesSince(r.mark) {
			for _, mod := range batch {
				assert.NotEqual(t, uint8(openflow.OFPFCDelete), mod.Command, "relaunch deleted %s", describeMods([]*openflow.FlowMod{mod}))
				assert.NotEqual(t, uint8(openflow.OFPFCDeleteStrict), mod.Command, "relaunch deleted %s", describeMods([]*openflow.FlowMod{mod}))
			}
		}
	})

	t.Run("every flow the predecessor left still matches", func(t *testing.T) {
		// A flow the relaunch re-adds takes its actions at once: the VNI's
		// flood list floods to the VTEPs the relaunch has learned.
		for _, flow := range r.oldFlows {
			identity, _, _ := strings.Cut(flow, " -> ")
			assert.NotEmpty(t, r.next.sw.matching(identity+" -> "), "relaunch dropped %s", flow)
		}
	})

	t.Run("a remote VTEP's flows hold until EVPN re-learns it", func(t *testing.T) {
		assert.True(t, r.next.sw.has(r.decapB), "VTEP B's decap authorisation is kept")
		assert.NotEmpty(t, r.next.sw.matching("10.0.0.2"))
	})

	t.Run("the flows the relaunch wants carry its generation", func(t *testing.T) {
		cookies := r.next.sw.cookies()
		assert.Positive(t, cookies[newCookie])
		assert.Positive(t, cookies[oldCookie], "the predecessor's flows the relaunch has not re-added keep its generation")
	})
}

func TestOverlaySweepsStaleGenerations(t *testing.T) {
	ctx := context.Background()

	t.Run("holds the predecessor's flows until the hold passes", func(t *testing.T) {
		r := newRelaunch(t)
		due := r.sweepDue()
		require.False(t, due.IsZero())

		r.next.handler.ndTick(ctx, due.Add(-time.Nanosecond))

		assert.Positive(t, r.next.sw.cookies()[r.old.cookie])
		assert.Equal(t, due, r.sweepDue())
	})

	t.Run("then deletes only older generations", func(t *testing.T) {
		r := newRelaunch(t)
		require.NoError(t, r.next.route(t, imet(ovlL2VNI, ovlVTEPC)))
		before := r.next.sw.cookies()

		r.next.handler.ndTick(ctx, r.sweepDue())

		after := r.next.sw.cookies()
		assert.Zero(t, after[r.old.cookie], "the predecessor's generation is swept")
		assert.Equal(t, before[r.next.handler.cookie], after[r.next.handler.cookie], "the relaunch's flows are untouched")
		assert.Equal(t, 1, after[foreignFirewallCookie], "another owner's flows are untouched")
		assert.Equal(t, 1, after[foreignPipelineCookie], "the pipeline's flows are untouched")
		assert.Empty(t, r.next.sw.matching("10.0.0.2"), "VTEP B, which no peer re-advertised, is gone")
		assert.NotEmpty(t, r.next.sw.matching("10.0.0.3"), "VTEP C, learned by the relaunch, stays")
		assert.True(t, r.sweepDue().IsZero())
	})

	t.Run("keeps a re-learned VTEP's flows", func(t *testing.T) {
		r := newRelaunch(t)
		require.NoError(t, r.next.route(t, imet(ovlL2VNI, ovlVTEPB)))

		r.next.handler.ndTick(ctx, r.sweepDue())

		assert.Zero(t, r.next.sw.cookies()[r.old.cookie])
		assert.NotEmpty(t, r.next.sw.matching("10.0.0.2"), "VTEP B's re-added flows carry the new generation")
	})

	t.Run("Stop removes every generation and no other owner's flows", func(t *testing.T) {
		r := newRelaunch(t)

		require.NoError(t, r.next.handler.Stop(ctx))

		cookies := r.next.sw.cookies()
		for cookie := range cookies {
			assert.NotEqual(t, OverlayCookie, cookie&ovs.OwnerCookieMask, "overlay generation %#x survived Stop", cookie)
		}
		assert.Equal(t, 1, cookies[foreignFirewallCookie])
		assert.Equal(t, 1, cookies[foreignPipelineCookie])
		assert.True(t, r.sweepDue().IsZero())
	})

	t.Run("a stopped overlay sweeps nothing", func(t *testing.T) {
		f := newStoppedOverlay(t, nil)
		f.sw.statsErr = errSwitchDown

		require.NoError(t, f.handler.sweepStaleGenerations(ctx))
		assert.Zero(t, f.sw.batchCount())
	})
}

func TestOverlaySweepStaleGenerationsErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		operation string
		breakIt   func(sw *fakeSwitch)
		fixIt     func(sw *fakeSwitch)
	}{
		{
			name:      "reading the flows fails",
			operation: "read stale generations",
			breakIt:   func(sw *fakeSwitch) { sw.statsErr = errSwitchDown },
			fixIt:     func(sw *fakeSwitch) { sw.statsErr = nil },
		},
		{
			name:      "deleting the flows fails",
			operation: "sweep stale generations",
			breakIt:   func(sw *fakeSwitch) { sw.fail(errSwitchDown) },
			fixIt:     func(sw *fakeSwitch) { sw.fail(nil) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRelaunch(t)
			due := r.sweepDue()
			tt.breakIt(r.next.sw)

			err := r.next.handler.sweepStaleGenerations(ctx)

			var flowErr *ErrFlowOperationFailed
			require.ErrorAs(t, err, &flowErr)
			assert.Equal(t, tt.operation, flowErr.Operation)
			assert.Equal(t, uint8(openflow.OFPTTAll), flowErr.Table)
			assert.ErrorIs(t, err, errSwitchDown)
			assert.Positive(t, r.next.sw.cookies()[r.old.cookie])
			assert.Equal(t, due, r.sweepDue(), "the sweep stays due")

			tt.fixIt(r.next.sw)
			r.next.handler.sweepPredecessor(ctx, due)
			assert.Zero(t, r.next.sw.cookies()[r.old.cookie], "the next tick retries")
		})
	}
}

func TestOverlayRevokeSweepsPredecessor(t *testing.T) {
	ctx := context.Background()

	t.Run("a revoked VTEP's predecessor flows go at once", func(t *testing.T) {
		r := newRelaunch(t)

		require.NoError(t, r.next.handler.RevokeVTEP(ctx, ovlVTEPB))

		assert.Empty(t, r.next.sw.matching("10.0.0.2"), "the predecessor's decap authorisation does not outlive the revocation")
		assert.Zero(t, r.next.sw.cookies()[r.old.cookie])
		assert.True(t, r.sweepDue().IsZero())
	})

	t.Run("a failed sweep is returned and retried on the next tick", func(t *testing.T) {
		r := newRelaunch(t)
		r.next.sw.statsErr = errSwitchDown

		err := r.next.handler.RevokeVTEP(ctx, ovlVTEPB)

		var flowErr *ErrFlowOperationFailed
		require.ErrorAs(t, err, &flowErr)
		assert.Equal(t, "read stale generations", flowErr.Operation)
		due := r.sweepDue()
		require.False(t, due.IsZero())
		assert.False(t, due.After(time.Now()), "the sweep is due now, not at the hold")

		r.next.sw.statsErr = nil
		r.next.handler.sweepPredecessor(ctx, due)
		assert.Empty(t, r.next.sw.matching("10.0.0.2"))
	})

	t.Run("with no predecessor pending it reads no flows", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		f.handler.mu.Lock()
		f.handler.staleSweepAt = time.Time{}
		f.handler.mu.Unlock()
		f.sw.statsErr = errSwitchDown

		require.NoError(t, f.handler.RevokeVTEP(ctx, ovlVTEPB))
		assert.Empty(t, f.sw.matching("10.0.0.2"))
	})
}

func TestOverlayUpgradeSweepsLegacyCookie(t *testing.T) {
	ctx := context.Background()

	t.Run("holds the older release's flows until the hold passes", func(t *testing.T) {
		r := newUpgrade(t)
		require.Positive(t, r.next.sw.cookies()[legacyOverlayCookie], "precondition: the older release's flows are on the switch")

		r.next.handler.ndTick(ctx, r.sweepDue().Add(-time.Nanosecond))

		assert.Positive(t, r.next.sw.cookies()[legacyOverlayCookie])
		assert.True(t, r.next.sw.has(r.decapB), "VTEP B's decap authorisation holds")
	})

	t.Run("then deletes them by exact cookie and nothing else", func(t *testing.T) {
		r := newUpgrade(t)
		require.NoError(t, r.next.route(t, imet(ovlL2VNI, ovlVTEPC)))
		before := r.next.sw.cookies()

		r.next.handler.ndTick(ctx, r.sweepDue())

		after := r.next.sw.cookies()
		assert.Zero(t, after[legacyOverlayCookie], "the older release's flows are swept")
		assert.Equal(t, before[r.next.handler.cookie], after[r.next.handler.cookie], "the upgrade's flows are untouched")
		assert.Equal(t, 1, after[foreignFirewallCookie], "another owner's flows are untouched")
		assert.Equal(t, 1, after[foreignPipelineCookie], "the pipeline's flows, which share the legacy cookie's owner bits, are untouched")
		assert.False(t, r.next.sw.has(r.decapB), "VTEP B's decap authorisation is gone")
		assert.Empty(t, r.next.sw.matching("10.0.0.2"), "VTEP B, which no peer re-advertised, is gone")
		assert.NotEmpty(t, r.next.sw.matching("10.0.0.3"), "VTEP C, learned by the upgrade, stays")
		assert.True(t, r.sweepDue().IsZero())
	})

	t.Run("Stop removes them and no other owner's flows", func(t *testing.T) {
		r := newUpgrade(t)

		require.NoError(t, r.next.handler.Stop(ctx))

		cookies := r.next.sw.cookies()
		assert.Zero(t, cookies[legacyOverlayCookie])
		assert.Equal(t, 1, cookies[foreignFirewallCookie])
		assert.Equal(t, 1, cookies[foreignPipelineCookie])
	})

	t.Run("a failed delete is a typed error and the sweep stays due", func(t *testing.T) {
		r := newUpgrade(t)
		due := r.sweepDue()
		r.next.sw.fail(errSwitchDown)

		err := r.next.handler.sweepStaleGenerations(ctx)

		var flowErr *ErrFlowOperationFailed
		require.ErrorAs(t, err, &flowErr)
		assert.Equal(t, "sweep stale generations", flowErr.Operation)
		assert.ErrorIs(t, err, errSwitchDown)
		assert.Positive(t, r.next.sw.cookies()[legacyOverlayCookie])
		assert.Equal(t, due, r.sweepDue())

		r.next.sw.fail(nil)
		r.next.handler.sweepPredecessor(ctx, due)
		assert.Zero(t, r.next.sw.cookies()[legacyOverlayCookie], "the next tick retries")
	})
}

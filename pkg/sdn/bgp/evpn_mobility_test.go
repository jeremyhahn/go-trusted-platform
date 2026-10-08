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

package bgp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	vtepA = netip.MustParseAddr("192.0.2.11")
	vtepB = netip.MustParseAddr("192.0.2.12")
	vtepC = netip.MustParseAddr("192.0.2.13")
)

// remoteMACRoute is a Type-2 route for codecHostMAC advertised by vtep.
func remoteMACRoute(vtep netip.Addr, ip string, seq uint32) *EVPNRouteData {
	route := &EVPNRouteData{
		Type:         EVPNTypeMACIPAdvertisement,
		RD:           RouteDistinguisher{Admin: vtep, Index: 1},
		RouteTargets: []RouteTarget{{AS: 65000, Value: 1<<28 | codecL2VNI}},
		MACIP:        &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI, VTEPIP: vtep, Sequence: seq},
		NextHop:      vtep,
	}
	if ip != "" {
		route.MACIP.IP = netip.MustParseAddr(ip)
	}
	return route
}

// withRemotes returns a state holding routes.
func withRemotes(routes ...*EVPNRouteData) *macState {
	state := newMACState()
	for _, route := range routes {
		state.remotes[route.Key()] = route
	}
	return state
}

func TestMobilityConfig_WithDefaults(t *testing.T) {
	assert.Equal(t, MobilityConfig{
		MaxMoves: DefaultMobilityMaxMoves,
		Window:   DefaultMobilityWindow,
		Hold:     DefaultMobilityHold,
	}, MobilityConfig{}.withDefaults())

	tuned := MobilityConfig{MaxMoves: 2, Window: time.Second, Hold: time.Minute}
	assert.Equal(t, tuned, tuned.withDefaults(), "set fields are kept")
	assert.Equal(t, DefaultMobilityMaxMoves, MobilityConfig{MaxMoves: -1}.withDefaults().MaxMoves, "a negative count is not a setting")
}

func TestMACState_RecordLocation(t *testing.T) {
	cfg := MobilityConfig{MaxMoves: 3, Window: time.Minute, Hold: 2 * time.Minute}
	now := time.Unix(1_700_000_000, 0)

	t.Run("first sighting and refreshes are not moves", func(t *testing.T) {
		s := newMACState()
		assert.False(t, s.recordLocation(vtepA, now, cfg))
		assert.False(t, s.recordLocation(vtepA, now, cfg))
		assert.Empty(t, s.moves)
		assert.Equal(t, vtepA, s.location)
	})

	t.Run("MaxMoves inside the window freezes the MAC for Hold", func(t *testing.T) {
		s := newMACState()
		s.recordLocation(vtepA, now, cfg)
		assert.False(t, s.recordLocation(vtepB, now.Add(time.Second), cfg))
		assert.False(t, s.recordLocation(vtepA, now.Add(2*time.Second), cfg))
		assert.True(t, s.recordLocation(vtepB, now.Add(3*time.Second), cfg))

		assert.True(t, s.frozen(now.Add(3*time.Second)))
		assert.True(t, s.frozen(now.Add(3*time.Second+cfg.Hold-time.Nanosecond)))
		assert.False(t, s.frozen(now.Add(3*time.Second+cfg.Hold)), "the hold ends")
		assert.Empty(t, s.moves, "a released MAC starts counting again")
	})

	t.Run("moves older than the window are forgotten", func(t *testing.T) {
		s := newMACState()
		s.recordLocation(vtepA, now, cfg)
		s.recordLocation(vtepB, now, cfg)
		s.recordLocation(vtepA, now.Add(time.Second), cfg)
		late := now.Add(cfg.Window + 500*time.Millisecond)
		assert.False(t, s.recordLocation(vtepB, late, cfg))
		assert.Len(t, s.moves, 2, "the move at 0s has left the window, the one at 1s has not")
		assert.False(t, s.frozen(late))
	})
}

func TestMACState_BestRemote(t *testing.T) {
	t.Run("nothing received", func(t *testing.T) {
		best, seq := newMACState().bestRemote()
		assert.False(t, best.IsValid())
		assert.Zero(t, seq)
	})

	t.Run("highest sequence wins", func(t *testing.T) {
		best, seq := withRemotes(remoteMACRoute(vtepA, "", 1), remoteMACRoute(vtepC, "", 4), remoteMACRoute(vtepB, "", 2)).bestRemote()
		assert.Equal(t, vtepC, best)
		assert.Equal(t, uint32(4), seq)
	})

	t.Run("a tie goes to the lowest VTEP address", func(t *testing.T) {
		best, seq := withRemotes(remoteMACRoute(vtepC, "", 2), remoteMACRoute(vtepB, "", 2)).bestRemote()
		assert.Equal(t, vtepB, best)
		assert.Equal(t, uint32(2), seq)
	})

	t.Run("a VTEP's sequence is the highest of its routes", func(t *testing.T) {
		s := withRemotes(remoteMACRoute(vtepB, "", 1), remoteMACRoute(vtepB, "10.1.0.10", 5), remoteMACRoute(vtepA, "", 5))
		best, seq := s.bestRemote()
		assert.Equal(t, vtepA, best, "A ties B at 5 and is lower")
		assert.Equal(t, uint32(5), seq)
		assert.Equal(t, uint32(5), s.remoteSequence(vtepB))
		assert.Zero(t, s.remoteSequence(vtepC))
		assert.Len(t, s.routesAt(vtepB), 2)
		assert.Empty(t, s.routesAt(vtepC))
	})
}

func TestRemoteBeatsLocal(t *testing.T) {
	for name, tc := range map[string]struct {
		remoteSeq, localSeq uint32
		remote, local       netip.Addr
		want                bool
	}{
		"higher sequence":          {2, 1, vtepB, vtepA, true},
		"lower sequence":           {1, 2, vtepA, vtepB, false},
		"tie, remote lower IP":     {3, 3, vtepA, vtepB, true},
		"tie, local lower IP":      {3, 3, vtepB, vtepA, false},
		"tie at zero, local lower": {0, 0, vtepC, vtepB, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, remoteBeatsLocal(tc.remoteSeq, tc.remote, tc.localSeq, tc.local))
		})
	}
}

func TestMACState_Idle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	assert.True(t, newMACState().idle(now))
	assert.False(t, withRemotes(remoteMACRoute(vtepA, "", 0)).idle(now), "a remote route")

	local := newMACState()
	local.local = &localMAC{mac: codecHostMAC, ips: map[netip.Addr]struct{}{{}: {}}}
	assert.False(t, local.idle(now), "a local route")

	frozen := newMACState()
	frozen.frozenUntil = now.Add(time.Minute)
	assert.False(t, frozen.idle(now), "a hold")
	assert.True(t, frozen.idle(now.Add(time.Minute)))
}

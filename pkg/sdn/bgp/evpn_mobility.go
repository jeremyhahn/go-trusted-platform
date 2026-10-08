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
	"net"
	"net/netip"
	"time"
)

// MAC Mobility (RFC 7432 §15): where a MAC is, by sequence number, and
// when it is moving too often to be believed.

const (
	// DefaultMobilityMaxMoves and DefaultMobilityWindow are the N and M of
	// RFC 7432 §15.1: N moves within M seconds is a duplicate MAC.
	DefaultMobilityMaxMoves = 5
	DefaultMobilityWindow   = 180 * time.Second

	// DefaultMobilityHold is how long a duplicate MAC stays frozen.
	DefaultMobilityHold = 180 * time.Second
)

// MobilityConfig tunes duplicate-MAC detection. Zero fields take the
// defaults.
type MobilityConfig struct {
	// MaxMoves is the number of moves within Window that freezes a MAC.
	MaxMoves int

	// Window is the period moves are counted over.
	Window time.Duration

	// Hold is how long a frozen MAC is neither advertised nor processed;
	// afterwards it is released with its move count reset.
	Hold time.Duration
}

// withDefaults fills the zero fields.
func (c MobilityConfig) withDefaults() MobilityConfig {
	if c.MaxMoves <= 0 {
		c.MaxMoves = DefaultMobilityMaxMoves
	}
	if c.Window <= 0 {
		c.Window = DefaultMobilityWindow
	}
	if c.Hold <= 0 {
		c.Hold = DefaultMobilityHold
	}
	return c
}

// localMAC is this VTEP's own advertisement of a MAC: the IPs bound to it
// (the zero address is the MAC-only route) and the sequence number every
// one of those routes carries.
type localMAC struct {
	mac net.HardwareAddr
	ips map[netip.Addr]struct{}
	seq uint32
}

// macState is everything known about one MAC in one VNI.
type macState struct {
	// local is this VTEP's advertisement; nil when the MAC is not here.
	local *localMAC

	// remotes are the imported Type-2 routes for the MAC, by route key.
	remotes map[string]*EVPNRouteData

	// activeVTEP is the remote VTEP the MAC is reached at; invalid when
	// the MAC is local or nowhere.
	activeVTEP netip.Addr

	// location is the last VTEP the MAC was seen at, this one included,
	// so that a move can be told from a refresh.
	location netip.Addr

	// moves are the times of the moves inside the detection window.
	moves []time.Time

	// frozenUntil is the end of a duplicate-MAC hold.
	frozenUntil time.Time
}

// newMACState returns an empty state.
func newMACState() *macState {
	return &macState{remotes: make(map[string]*EVPNRouteData)}
}

// frozen reports whether the MAC is held as a duplicate at now.
func (s *macState) frozen(now time.Time) bool {
	return now.Before(s.frozenUntil)
}

// recordLocation notes the MAC at vtep and reports whether that move made
// it a duplicate, which freezes it for cfg.Hold.
func (s *macState) recordLocation(vtep netip.Addr, now time.Time, cfg MobilityConfig) bool {
	moved := s.location.IsValid() && s.location != vtep
	s.location = vtep
	if !moved {
		return false
	}
	kept := s.moves[:0]
	for _, at := range s.moves {
		if now.Sub(at) < cfg.Window {
			kept = append(kept, at)
		}
	}
	s.moves = append(kept, now)
	if len(s.moves) < cfg.MaxMoves {
		return false
	}
	s.moves = nil
	s.frozenUntil = now.Add(cfg.Hold)
	return true
}

// remoteSequence returns the highest sequence number vtep advertises for
// the MAC.
func (s *macState) remoteSequence(vtep netip.Addr) uint32 {
	var seq uint32
	for _, route := range s.remotes {
		if route.MACIP.VTEPIP == vtep && route.MACIP.Sequence > seq {
			seq = route.MACIP.Sequence
		}
	}
	return seq
}

// bestRemote returns the remote VTEP that wins the MAC: the highest
// sequence number, and on a tie the lowest address (RFC 7432 §15.1).
func (s *macState) bestRemote() (netip.Addr, uint32) {
	var best netip.Addr
	var bestSeq uint32
	for _, route := range s.remotes {
		vtep, seq := route.MACIP.VTEPIP, route.MACIP.Sequence
		if !best.IsValid() || seq > bestSeq || (seq == bestSeq && vtep.Less(best)) {
			best, bestSeq = vtep, seq
		}
	}
	if best.IsValid() {
		bestSeq = s.remoteSequence(best)
	}
	return best, bestSeq
}

// remoteBeatsLocal reports whether a remote route displaces this VTEP's
// own advertisement: a higher sequence number, or an equal one from a
// lower address.
func remoteBeatsLocal(remoteSeq uint32, remote netip.Addr, localSeq uint32, local netip.Addr) bool {
	return remoteSeq > localSeq || (remoteSeq == localSeq && remote.Less(local))
}

// routesAt returns the remote routes advertised by vtep.
func (s *macState) routesAt(vtep netip.Addr) []*EVPNRouteData {
	var routes []*EVPNRouteData
	for _, route := range s.remotes {
		if route.MACIP.VTEPIP == vtep {
			routes = append(routes, route)
		}
	}
	return routes
}

// idle reports whether the state holds nothing worth keeping: no route
// and no hold. A move always comes with a route, so the move history of a
// MAC that is nowhere is not needed.
func (s *macState) idle(now time.Time) bool {
	return s.local == nil && len(s.remotes) == 0 && !s.frozen(now)
}

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

package fhrp

import (
	"net/netip"
	"time"
)

// State is a group's RFC 5798 §6.4 state.
type State uint8

const (
	// StateInitialize: not participating; the state a group is created in
	// and returns to on shutdown.
	StateInitialize State = iota
	// StateBackup: listening for the master, ready to take over.
	StateBackup
	// StateMaster: holding the virtual addresses and advertising.
	StateMaster
)

// String implements fmt.Stringer.
func (s State) String() string {
	switch s {
	case StateInitialize:
		return "initialize"
	case StateBackup:
		return "backup"
	case StateMaster:
		return "master"
	default:
		return "unknown"
	}
}

// Actuator is what a group asks the outside world to do. The speaker
// implements it over a Transport and a Programmer; tests record the calls.
type Actuator interface {
	// Advertise sends an ADVERTISEMENT with the given priority.
	Advertise(g *Group, priority uint8) error
	// Claim programs the virtual addresses on the interface and announces
	// them (gratuitous ARP / unsolicited neighbour advertisement).
	Claim(g *Group) error
	// Release removes the virtual addresses from the interface.
	Release(g *Group) error
}

// Group is the state machine for one virtual router. It is deterministic:
// every method takes the current time, so tests drive it without a clock
// and the speaker drives it from one goroutine per group.
type Group struct {
	cfg      GroupConfig
	family   Family
	source   netip.Addr
	prefixes []netip.Prefix
	act      Actuator

	state State
	// masterAdverInterval is the interval used for Master_Down_Interval: the
	// local one until a master is heard, then the master's (§6.4.2).
	masterAdverInterval uint16
	// masterDownAt is when Master_Down_Timer fires (Backup only).
	masterDownAt time.Time
	// nextAdvertAt is when Adver_Timer fires (Master only).
	nextAdvertAt time.Time
	// lastErr is the last actuator failure, surfaced through Health.
	lastErr error
	// transitions counts state changes, for telemetry and tests.
	transitions uint64
}

// NewGroup builds a group from a validated configuration.
func NewGroup(cfg GroupConfig, act Actuator) (*Group, error) {
	src, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	if act == nil {
		return nil, &ErrTransportRequired{Dependency: "actuator"}
	}
	return &Group{
		cfg:                 cfg,
		family:              cfg.family(),
		source:              src,
		prefixes:            cfg.prefixes(),
		act:                 act,
		state:               StateInitialize,
		masterAdverInterval: cfg.effectiveInterval(),
	}, nil
}

// Config returns the group's configuration.
func (g *Group) Config() GroupConfig { return g.cfg }

// Family returns the group's address family.
func (g *Group) Family() Family { return g.family }

// State returns the current state.
func (g *Group) State() State { return g.state }

// Source is the address advertisements are sent from.
func (g *Group) Source() netip.Addr { return g.source }

// Addresses returns the virtual addresses without prefix length, in the
// order they are advertised.
func (g *Group) Addresses() []netip.Addr {
	out := make([]netip.Addr, 0, len(g.prefixes))
	for _, p := range g.prefixes {
		out = append(out, p.Addr())
	}
	return out
}

// Prefixes returns the virtual addresses with their prefix length.
func (g *Group) Prefixes() []netip.Prefix { return g.prefixes }

// Priority is the local priority.
func (g *Group) Priority() uint8 { return g.cfg.effectivePriority() }

// AdvertInterval is the local Master_Adver_Interval.
func (g *Group) AdvertInterval() time.Duration {
	return centiseconds(g.cfg.effectiveInterval())
}

// Transitions returns how many state changes the group has made.
func (g *Group) Transitions() uint64 { return g.transitions }

// LastError returns the most recent actuator failure, if any.
func (g *Group) LastError() error { return g.lastErr }

// SkewTime is ((256 − Priority) × Master_Adver_Interval) / 256 (§6.1),
// using the interval currently in force.
func (g *Group) SkewTime() time.Duration {
	cs := (uint32(256-uint32(g.Priority())) * uint32(g.masterAdverInterval)) / 256
	return centiseconds(uint16(cs))
}

// MasterDownInterval is 3 × Master_Adver_Interval + Skew_Time (§6.1).
func (g *Group) MasterDownInterval() time.Duration {
	return 3*centiseconds(g.masterAdverInterval) + g.SkewTime()
}

// NextDeadline is when the group next needs Tick, or the zero time when it
// has no timer running (Initialize).
func (g *Group) NextDeadline() time.Time {
	switch g.state {
	case StateBackup:
		return g.masterDownAt
	case StateMaster:
		return g.nextAdvertAt
	default:
		return time.Time{}
	}
}

// Startup performs the Initialize transitions of §6.4.1: the address owner
// becomes Master at once; everyone else becomes Backup and waits
// Master_Down_Interval.
func (g *Group) Startup(now time.Time) error {
	if g.state != StateInitialize {
		return nil
	}
	if g.Priority() == PriorityOwner {
		return g.becomeMaster(now)
	}
	g.masterAdverInterval = g.cfg.effectiveInterval()
	g.masterDownAt = now.Add(g.MasterDownInterval())
	g.setState(StateBackup)
	return nil
}

// Shutdown performs the Shutdown event: a Master sends a priority-0
// advertisement and releases the addresses; a Backup simply stops.
func (g *Group) Shutdown(now time.Time) error {
	switch g.state {
	case StateMaster:
		var first error
		if err := g.act.Advertise(g, PriorityRelease); err != nil {
			first = err
		}
		if err := g.act.Release(g); err != nil && first == nil {
			first = err
		}
		g.setState(StateInitialize)
		g.lastErr = first
		return first
	case StateBackup:
		g.setState(StateInitialize)
		return nil
	default:
		return nil
	}
}

// Tick fires whichever timer is due at now (§6.4.2 Master_Down_Timer,
// §6.4.3 Adver_Timer). Calling it early is a no-op.
func (g *Group) Tick(now time.Time) error {
	switch g.state {
	case StateBackup:
		if now.Before(g.masterDownAt) {
			return nil
		}
		return g.becomeMaster(now)
	case StateMaster:
		if now.Before(g.nextAdvertAt) {
			return nil
		}
		g.nextAdvertAt = now.Add(g.AdvertInterval())
		return g.advertise()
	default:
		return nil
	}
}

// HandleAdvertisement applies a received advertisement for this group
// (§6.4.2 / §6.4.3). The caller has already matched VRID and family and
// verified the packet; sender is the packet's source address.
func (g *Group) HandleAdvertisement(adv *Advertisement, sender netip.Addr, now time.Time) error {
	if adv == nil {
		return &ErrInvalidPacket{Reason: "nil advertisement"}
	}
	switch g.state {
	case StateBackup:
		if adv.Priority == PriorityRelease {
			// The master is leaving: take over after Skew_Time.
			g.masterDownAt = now.Add(g.SkewTime())
			return nil
		}
		if !g.cfg.preempts() || adv.Priority >= g.Priority() {
			g.masterAdverInterval = adv.MaxAdvertInterval
			g.masterDownAt = now.Add(g.MasterDownInterval())
		}
		// A lower-priority master while preempting: discard and let the
		// Master_Down_Timer expire.
		return nil
	case StateMaster:
		if adv.Priority == PriorityRelease {
			g.nextAdvertAt = now.Add(g.AdvertInterval())
			return g.advertise()
		}
		if adv.Priority > g.Priority() || (adv.Priority == g.Priority() && sender.Compare(g.source) > 0) {
			g.masterAdverInterval = adv.MaxAdvertInterval
			g.masterDownAt = now.Add(g.MasterDownInterval())
			err := g.act.Release(g)
			g.setState(StateBackup)
			g.lastErr = err
			return err
		}
		return nil
	default:
		return nil
	}
}

func (g *Group) becomeMaster(now time.Time) error {
	g.setState(StateMaster)
	g.nextAdvertAt = now.Add(g.AdvertInterval())
	var first error
	if err := g.advertise(); err != nil {
		first = err
	}
	if err := g.act.Claim(g); err != nil && first == nil {
		first = err
	}
	g.lastErr = first
	return first
}

func (g *Group) advertise() error {
	err := g.act.Advertise(g, g.Priority())
	g.lastErr = err
	if err != nil {
		return &ErrTransportFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "advertise", Cause: err}
	}
	return nil
}

func (g *Group) setState(s State) {
	if g.state != s {
		g.state = s
		g.transitions++
	}
}

// advertisement builds this group's ADVERTISEMENT with the given priority.
func (g *Group) advertisement(priority uint8) *Advertisement {
	return &Advertisement{
		VRID:              g.cfg.VRID,
		Priority:          priority,
		MaxAdvertInterval: g.cfg.effectiveInterval(),
		Addresses:         g.Addresses(),
	}
}

func centiseconds(cs uint16) time.Duration {
	return time.Duration(cs) * 10 * time.Millisecond
}

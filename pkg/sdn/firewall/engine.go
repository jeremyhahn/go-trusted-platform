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

// Package firewall implements a pure-Go stateful firewall engine with
// connection tracking, zone-based policy, NAT, and priority-ordered rules.
// It is designed for data-plane packet processing with sub-microsecond
// latency on the established connection fast path.
package firewall

import (
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"
)

// Direction indicates the direction of packet flow.
type Direction uint8

const (
	// DirectionIngress is traffic entering the system.
	DirectionIngress Direction = iota

	// DirectionEgress is traffic leaving the system.
	DirectionEgress
)

// PacketInfo holds parsed packet metadata for rule matching. This struct
// is allocated once per packet and passed through the processing pipeline.
type PacketInfo struct {
	// SrcIP is the source IP address.
	SrcIP netip.Addr

	// DstIP is the destination IP address.
	DstIP netip.Addr

	// SrcPort is the source transport port.
	SrcPort uint16

	// DstPort is the destination transport port.
	DstPort uint16

	// Protocol is the IP protocol number (TCP=6, UDP=17, ICMP=1).
	Protocol uint8

	// InIface is the incoming network interface name.
	InIface string

	// OutIface is the outgoing network interface name. Empty for local input.
	OutIface string

	// Length is the total packet length in bytes.
	Length int

	// SrcZone is the resolved source zone name. Set by the engine during
	// processing; not provided by the caller.
	SrcZone string

	// DstZone is the resolved destination zone name. Set by the engine
	// during processing; not provided by the caller.
	DstZone string

	// ConnState is the connection state for this packet. Set by the engine
	// during processing; not provided by the caller.
	ConnState ConnState
}

// EngineStats holds atomic counters for firewall engine statistics.
type EngineStats struct {
	// PacketsProcessed is the total number of packets evaluated.
	PacketsProcessed atomic.Uint64

	// PacketsAllowed is the number of packets permitted.
	PacketsAllowed atomic.Uint64

	// PacketsDenied is the number of packets dropped or rejected.
	PacketsDenied atomic.Uint64

	// PacketsNATted is the number of packets with NAT applied.
	PacketsNATted atomic.Uint64

	// ActiveConnections is the current number of tracked connections.
	ActiveConnections atomic.Int64
}

// EngineStatsSnapshot is a plain-value copy of the engine counters at
// a point in time. Stats returns this type instead of EngineStats so
// callers never copy the live atomic counters (which carry noCopy
// semantics).
type EngineStatsSnapshot struct {
	// PacketsProcessed is the total number of packets evaluated.
	PacketsProcessed uint64

	// PacketsAllowed is the number of packets permitted.
	PacketsAllowed uint64

	// PacketsDenied is the number of packets dropped or rejected.
	PacketsDenied uint64

	// PacketsNATted is the number of packets with NAT applied.
	PacketsNATted uint64

	// ActiveConnections is the current number of tracked connections.
	ActiveConnections int64
}

// Engine is the stateful firewall packet processor. It combines
// connection tracking, zone-based policy, NAT, and priority-ordered
// rules into a single evaluation pipeline.
type Engine struct {
	conntrack     *ConnTrack
	rules         []Rule
	natEngine     *NATEngine
	zones         *ZoneResolver
	defaultPolicy Action
	logger        *slog.Logger
	stats         EngineStats
}

// NewEngine creates a firewall engine from the given configuration.
func NewEngine(config *Config, logger *slog.Logger) (*Engine, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	defaultPolicy := parseAction(config.DefaultPolicy)

	timeouts := config.Timeouts
	if timeouts.TCPEstablished == 0 {
		timeouts = DefaultTimeouts()
	}

	rules := make([]Rule, len(config.Rules))
	copy(rules, config.Rules)
	sortRules(rules)

	var allNATRules []NATRule
	allNATRules = append(allNATRules, config.NAT.SNAT...)
	allNATRules = append(allNATRules, config.NAT.DNAT...)

	return &Engine{
		conntrack:     NewConnTrack(timeouts, logger),
		rules:         rules,
		natEngine:     NewNATEngine(allNATRules, logger),
		zones:         NewZoneResolver(config.Zones),
		defaultPolicy: defaultPolicy,
		logger:        logger,
	}, nil
}

// Process evaluates a packet against the firewall rules and connection
// tracking table. It returns the action to take and an optional NAT
// translation entry.
//
// This is the hot path. For established connections it performs a single
// sharded map lookup under a read lock with no allocations.
func (e *Engine) Process(pkt *PacketInfo) (Action, *NATEntry) {
	e.stats.PacketsProcessed.Add(1)

	// Resolve zones from interface names.
	if pkt.InIface != "" {
		pkt.SrcZone, _ = e.zones.ZoneForInterface(pkt.InIface)
	}
	if pkt.OutIface != "" {
		pkt.DstZone, _ = e.zones.ZoneForInterface(pkt.OutIface)
	}

	tuple := FiveTuple{
		SrcIP:    pkt.SrcIP,
		DstIP:    pkt.DstIP,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
		Protocol: pkt.Protocol,
	}

	// Fast path: check conntrack for existing connection.
	if entry, ok := e.conntrack.Lookup(tuple); ok {
		if entry.State == ConnStateEstablished || entry.State == ConnStateRelated {
			pkt.ConnState = entry.State
			now := time.Now()
			e.conntrack.Update(tuple, func(ce *ConnEntry) {
				ce.LastSeen = now
				ce.Packets++
				ce.Bytes += uint64(pkt.Length)
			})
			e.stats.PacketsAllowed.Add(1)
			return ActionAllow, entry.NATInfo
		}
		pkt.ConnState = entry.State
	} else {
		pkt.ConnState = ConnStateNew
	}

	// Check NAT rules.
	var direction Direction
	if pkt.OutIface != "" {
		direction = DirectionEgress
	}
	natEntry := e.natEngine.Apply(pkt, direction)
	if natEntry != nil {
		e.stats.PacketsNATted.Add(1)
	}

	// Evaluate firewall rules in priority order.
	action := e.evaluateRules(pkt)

	// Update stats and conntrack.
	if action == ActionAllow {
		e.stats.PacketsAllowed.Add(1)
		now := time.Now()
		e.conntrack.Insert(&ConnEntry{
			Tuple:    tuple,
			State:    ConnStateNew,
			Created:  now,
			LastSeen: now,
			Packets:  1,
			Bytes:    uint64(pkt.Length),
			NATInfo:  natEntry,
		})
		e.stats.ActiveConnections.Store(int64(e.conntrack.Count()))
	} else {
		e.stats.PacketsDenied.Add(1)
	}

	return action, natEntry
}

// MarkEstablished transitions a connection from NEW to ESTABLISHED.
// This should be called when reply traffic is seen for a tracked connection.
func (e *Engine) MarkEstablished(tuple FiveTuple) {
	e.conntrack.Update(tuple, func(ce *ConnEntry) {
		if ce.State == ConnStateNew {
			ce.State = ConnStateEstablished
		}
	})
}

// evaluateRules walks the sorted rule list and returns the action of
// the first matching rule. Returns the engine default policy if no
// rule matches.
func (e *Engine) evaluateRules(pkt *PacketInfo) Action {
	for i := range e.rules {
		if e.rules[i].Matches(pkt) {
			return e.rules[i].Action
		}
	}
	return e.defaultPolicy
}

// Stats returns a snapshot of the engine statistics.
func (e *Engine) Stats() EngineStatsSnapshot {
	return EngineStatsSnapshot{
		PacketsProcessed:  e.stats.PacketsProcessed.Load(),
		PacketsAllowed:    e.stats.PacketsAllowed.Load(),
		PacketsDenied:     e.stats.PacketsDenied.Load(),
		PacketsNATted:     e.stats.PacketsNATted.Load(),
		ActiveConnections: e.stats.ActiveConnections.Load(),
	}
}

// ConnTrackCount returns the number of active tracked connections.
func (e *Engine) ConnTrackCount() int {
	return e.conntrack.Count()
}

// ExpireConnections removes expired connection tracking entries.
// Returns the number of entries removed.
func (e *Engine) ExpireConnections(now time.Time) int {
	removed := e.conntrack.Expire(now)
	e.stats.ActiveConnections.Store(int64(e.conntrack.Count()))
	return removed
}

// ConnTrackSnapshot returns a copy of all tracked connections for
// replication purposes.
func (e *Engine) ConnTrackSnapshot() []*ConnEntry {
	return e.conntrack.Snapshot()
}

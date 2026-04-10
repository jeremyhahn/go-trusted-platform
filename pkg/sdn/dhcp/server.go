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

package dhcp

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// IPAllocator allocates IP addresses from a pool.
type IPAllocator interface {
	// Allocate allocates an IP address for the given MAC.
	Allocate(ctx context.Context, poolID string, mac net.HardwareAddr) (netip.Addr, error)

	// AllocateSpecific attempts to allocate a specific IP address.
	AllocateSpecific(ctx context.Context, poolID string, mac net.HardwareAddr, ip netip.Addr) error

	// Release releases an allocated IP address.
	Release(ctx context.Context, poolID string, ip netip.Addr) error

	// IsAllocated checks if an IP is currently allocated.
	IsAllocated(ctx context.Context, poolID string, ip netip.Addr) (bool, error)
}

// statsCollector provides lock-free statistics collection using atomics.
// This is an unexported type used internally by server implementations.
type statsCollector struct {
	startedAt       atomic.Value // time.Time
	packetsReceived atomic.Uint64
	packetsSent     atomic.Uint64
	discoverCount   atomic.Uint64
	offerCount      atomic.Uint64
	requestCount    atomic.Uint64
	ackCount        atomic.Uint64
	nakCount        atomic.Uint64
	releaseCount    atomic.Uint64
	declineCount    atomic.Uint64
	informCount     atomic.Uint64
	errorCount      atomic.Uint64
	activeLeases    atomic.Int64
}

// newStatsCollector creates a new statistics collector.
func newStatsCollector() *statsCollector {
	s := &statsCollector{}
	s.startedAt.Store(time.Time{})
	return s
}

// start marks the server as started.
func (s *statsCollector) start() {
	s.startedAt.Store(time.Now())
}

// reset resets all statistics.
func (s *statsCollector) reset() {
	s.startedAt.Store(time.Time{})
	s.packetsReceived.Store(0)
	s.packetsSent.Store(0)
	s.discoverCount.Store(0)
	s.offerCount.Store(0)
	s.requestCount.Store(0)
	s.ackCount.Store(0)
	s.nakCount.Store(0)
	s.releaseCount.Store(0)
	s.declineCount.Store(0)
	s.informCount.Store(0)
	s.errorCount.Store(0)
	s.activeLeases.Store(0)
}

// incPacketsReceived increments the packets received counter.
func (s *statsCollector) incPacketsReceived() {
	s.packetsReceived.Add(1)
}

// incPacketsSent increments the packets sent counter.
func (s *statsCollector) incPacketsSent() {
	s.packetsSent.Add(1)
}

// incDiscover increments the discover counter.
func (s *statsCollector) incDiscover() {
	s.discoverCount.Add(1)
}

// incOffer increments the offer counter.
func (s *statsCollector) incOffer() {
	s.offerCount.Add(1)
}

// incRequest increments the request counter.
func (s *statsCollector) incRequest() {
	s.requestCount.Add(1)
}

// incAck increments the ack counter.
func (s *statsCollector) incAck() {
	s.ackCount.Add(1)
}

// incNak increments the nak counter.
func (s *statsCollector) incNak() {
	s.nakCount.Add(1)
}

// incRelease increments the release counter.
func (s *statsCollector) incRelease() {
	s.releaseCount.Add(1)
}

// incDecline increments the decline counter.
func (s *statsCollector) incDecline() {
	s.declineCount.Add(1)
}

// incInform increments the inform counter.
func (s *statsCollector) incInform() {
	s.informCount.Add(1)
}

// incError increments the error counter.
func (s *statsCollector) incError() {
	s.errorCount.Add(1)
}

// setActiveLeases sets the active leases count.
func (s *statsCollector) setActiveLeases(count int) {
	s.activeLeases.Store(int64(count))
}

// incActiveLeases increments the active leases count.
func (s *statsCollector) incActiveLeases() {
	s.activeLeases.Add(1)
}

// decActiveLeases decrements the active leases count.
func (s *statsCollector) decActiveLeases() {
	s.activeLeases.Add(-1)
}

// snapshot returns a copy of the current statistics.
func (s *statsCollector) snapshot() ServerStats {
	startedAt, _ := s.startedAt.Load().(time.Time)
	return ServerStats{
		StartedAt:       startedAt,
		PacketsReceived: s.packetsReceived.Load(),
		PacketsSent:     s.packetsSent.Load(),
		DiscoverCount:   s.discoverCount.Load(),
		OfferCount:      s.offerCount.Load(),
		RequestCount:    s.requestCount.Load(),
		AckCount:        s.ackCount.Load(),
		NakCount:        s.nakCount.Load(),
		ReleaseCount:    s.releaseCount.Load(),
		DeclineCount:    s.declineCount.Load(),
		InformCount:     s.informCount.Load(),
		ErrorCount:      s.errorCount.Load(),
		ActiveLeases:    int(s.activeLeases.Load()),
	}
}

// StatsCollector provides lock-free statistics collection using atomics.
// This is an exported type for external use and testing.
type StatsCollector struct {
	inner *statsCollector
}

// NewStatsCollector creates a new statistics collector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{inner: newStatsCollector()}
}

// Start marks the server as started.
func (s *StatsCollector) Start() {
	s.inner.start()
}

// Reset resets all statistics.
func (s *StatsCollector) Reset() {
	s.inner.reset()
}

// IncPacketsReceived increments the packets received counter.
func (s *StatsCollector) IncPacketsReceived() {
	s.inner.incPacketsReceived()
}

// IncPacketsSent increments the packets sent counter.
func (s *StatsCollector) IncPacketsSent() {
	s.inner.incPacketsSent()
}

// IncDiscover increments the discover counter.
func (s *StatsCollector) IncDiscover() {
	s.inner.incDiscover()
}

// IncOffer increments the offer counter.
func (s *StatsCollector) IncOffer() {
	s.inner.incOffer()
}

// IncRequest increments the request counter.
func (s *StatsCollector) IncRequest() {
	s.inner.incRequest()
}

// IncAck increments the ack counter.
func (s *StatsCollector) IncAck() {
	s.inner.incAck()
}

// IncNak increments the nak counter.
func (s *StatsCollector) IncNak() {
	s.inner.incNak()
}

// IncRelease increments the release counter.
func (s *StatsCollector) IncRelease() {
	s.inner.incRelease()
}

// IncDecline increments the decline counter.
func (s *StatsCollector) IncDecline() {
	s.inner.incDecline()
}

// IncInform increments the inform counter.
func (s *StatsCollector) IncInform() {
	s.inner.incInform()
}

// IncError increments the error counter.
func (s *StatsCollector) IncError() {
	s.inner.incError()
}

// SetActiveLeases sets the active leases count.
func (s *StatsCollector) SetActiveLeases(count int) {
	s.inner.setActiveLeases(count)
}

// IncActiveLeases increments the active leases count.
func (s *StatsCollector) IncActiveLeases() {
	s.inner.incActiveLeases()
}

// DecActiveLeases decrements the active leases count.
func (s *StatsCollector) DecActiveLeases() {
	s.inner.decActiveLeases()
}

// Snapshot returns a copy of the current statistics.
func (s *StatsCollector) Snapshot() ServerStats {
	return s.inner.snapshot()
}

// MessageType represents a DHCP message type.
type MessageType byte

const (
	// MessageTypeDiscover is DHCPDISCOVER.
	MessageTypeDiscover MessageType = 1

	// MessageTypeOffer is DHCPOFFER.
	MessageTypeOffer MessageType = 2

	// MessageTypeRequest is DHCPREQUEST.
	MessageTypeRequest MessageType = 3

	// MessageTypeDecline is DHCPDECLINE.
	MessageTypeDecline MessageType = 4

	// MessageTypeAck is DHCPACK.
	MessageTypeAck MessageType = 5

	// MessageTypeNak is DHCPNAK.
	MessageTypeNak MessageType = 6

	// MessageTypeRelease is DHCPRELEASE.
	MessageTypeRelease MessageType = 7

	// MessageTypeInform is DHCPINFORM.
	MessageTypeInform MessageType = 8
)

// String returns the string representation of the message type.
func (m MessageType) String() string {
	if s, ok := messageTypeStrings[m]; ok {
		return s
	}
	return "UNKNOWN"
}

// IsValid returns true if the message type is valid.
func (m MessageType) IsValid() bool {
	return m >= MessageTypeDiscover && m <= MessageTypeInform
}

// messageTypeStrings provides map-based dispatch for DHCP message types.
// This enables O(1) constant-time lookup instead of switch statements.
var messageTypeStrings = map[MessageType]string{
	MessageTypeDiscover: "DISCOVER",
	MessageTypeOffer:    "OFFER",
	MessageTypeRequest:  "REQUEST",
	MessageTypeDecline:  "DECLINE",
	MessageTypeAck:      "ACK",
	MessageTypeNak:      "NAK",
	MessageTypeRelease:  "RELEASE",
	MessageTypeInform:   "INFORM",
}

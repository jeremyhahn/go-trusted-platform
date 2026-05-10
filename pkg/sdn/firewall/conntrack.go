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

package firewall

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
)

const (
	// connTrackShardCount is the number of shards in the connection
	// tracking table. Must be a power of two for fast modulo via bitmask.
	connTrackShardCount = 256

	// connTrackShardMask is the bitmask for shard selection.
	connTrackShardMask = connTrackShardCount - 1

	// ProtocolTCP is the IP protocol number for TCP.
	ProtocolTCP uint8 = 6

	// ProtocolUDP is the IP protocol number for UDP.
	ProtocolUDP uint8 = 17

	// ProtocolICMP is the IP protocol number for ICMP.
	ProtocolICMP uint8 = 1
)

// ConnState represents the state of a tracked connection.
type ConnState uint8

const (
	// ConnStateNew indicates a newly seen connection.
	ConnStateNew ConnState = iota

	// ConnStateEstablished indicates a connection with bidirectional traffic.
	ConnStateEstablished

	// ConnStateRelated indicates a connection related to an existing one.
	ConnStateRelated

	// ConnStateInvalid indicates a connection that does not match any
	// known state transition.
	ConnStateInvalid
)

// String returns the human-readable name of the connection state.
func (s ConnState) String() string {
	name, ok := connStateNames[s]
	if !ok {
		return "UNKNOWN"
	}
	return name
}

var connStateNames = map[ConnState]string{
	ConnStateNew:         "NEW",
	ConnStateEstablished: "ESTABLISHED",
	ConnStateRelated:     "RELATED",
	ConnStateInvalid:     "INVALID",
}

// ConnTrackTimeouts configures the idle timeouts for tracked connections.
type ConnTrackTimeouts struct {
	// TCPEstablished is the timeout for established TCP connections.
	TCPEstablished time.Duration `yaml:"tcp-established,omitempty" json:"tcp_established,omitempty" mapstructure:"tcp-established"`

	// TCPClose is the timeout for TCP connections in close states.
	TCPClose time.Duration `yaml:"tcp-close,omitempty" json:"tcp_close,omitempty" mapstructure:"tcp-close"`

	// UDP is the timeout for UDP flows.
	UDP time.Duration `yaml:"udp,omitempty" json:"udp,omitempty" mapstructure:"udp"`

	// ICMP is the timeout for ICMP flows.
	ICMP time.Duration `yaml:"icmp,omitempty" json:"icmp,omitempty" mapstructure:"icmp"`
}

// FiveTuple uniquely identifies a network connection by its source and
// destination addresses, ports, and protocol.
type FiveTuple struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// hash computes a deterministic hash of the five-tuple using xxhash.
// The buffer is allocated on the stack (37 bytes for IPv6).
func (t *FiveTuple) hash() uint64 {
	// IPv4: 4+4+2+2+1 = 13 bytes, IPv6: 16+16+2+2+1 = 37 bytes
	var buf [37]byte
	n := 0
	src := t.SrcIP.As16()
	dst := t.DstIP.As16()
	if t.SrcIP.Is4() {
		s4 := t.SrcIP.As4()
		d4 := t.DstIP.As4()
		copy(buf[0:4], s4[:])
		copy(buf[4:8], d4[:])
		n = 8
	} else {
		copy(buf[0:16], src[:])
		copy(buf[16:32], dst[:])
		n = 32
	}
	binary.LittleEndian.PutUint16(buf[n:n+2], t.SrcPort)
	n += 2
	binary.LittleEndian.PutUint16(buf[n:n+2], t.DstPort)
	n += 2
	buf[n] = t.Protocol
	n++
	return xxhash.Sum64(buf[:n])
}

// ConnEntry tracks the state of a single connection.
type ConnEntry struct {
	// Tuple is the five-tuple that identifies this connection.
	Tuple FiveTuple

	// State is the current connection state.
	State ConnState

	// Created is the time the connection was first seen.
	Created time.Time

	// LastSeen is the time the connection was last seen.
	LastSeen time.Time

	// Packets is the total packet count for this connection.
	Packets uint64

	// Bytes is the total byte count for this connection.
	Bytes uint64

	// NATInfo holds NAT translation data, or nil if no NAT is applied.
	NATInfo *NATEntry
}

// connTrackShard is a single shard of the connection tracking table.
type connTrackShard struct {
	mu      sync.RWMutex
	entries map[FiveTuple]*ConnEntry
}

// ConnTrack is a high-performance sharded connection tracking table.
// Lookups use a read lock on a single shard selected by hashing the
// five-tuple, providing high concurrency for the packet processing path.
type ConnTrack struct {
	shards  [connTrackShardCount]connTrackShard
	timeout ConnTrackTimeouts
	count   atomic.Int64
	logger  *slog.Logger
}

// NewConnTrack creates a connection tracking table with the given
// timeouts. Zero-value timeouts are replaced with defaults.
func NewConnTrack(timeouts ConnTrackTimeouts, logger *slog.Logger) *ConnTrack {
	if timeouts.TCPEstablished == 0 {
		timeouts.TCPEstablished = DefaultTimeouts().TCPEstablished
	}
	if timeouts.TCPClose == 0 {
		timeouts.TCPClose = DefaultTimeouts().TCPClose
	}
	if timeouts.UDP == 0 {
		timeouts.UDP = DefaultTimeouts().UDP
	}
	if timeouts.ICMP == 0 {
		timeouts.ICMP = DefaultTimeouts().ICMP
	}
	ct := &ConnTrack{
		timeout: timeouts,
		logger:  logger,
	}
	for i := range ct.shards {
		ct.shards[i].entries = make(map[FiveTuple]*ConnEntry)
	}
	return ct
}

// shard returns the shard for the given five-tuple.
func (ct *ConnTrack) shard(tuple FiveTuple) *connTrackShard {
	h := tuple.hash()
	return &ct.shards[h&connTrackShardMask]
}

// Lookup retrieves a connection entry by its five-tuple. The returned
// entry must not be modified without calling Update.
func (ct *ConnTrack) Lookup(tuple FiveTuple) (*ConnEntry, bool) {
	s := ct.shard(tuple)
	s.mu.RLock()
	entry, ok := s.entries[tuple]
	s.mu.RUnlock()
	return entry, ok
}

// Insert adds a new connection entry to the tracking table.
func (ct *ConnTrack) Insert(entry *ConnEntry) {
	s := ct.shard(entry.Tuple)
	s.mu.Lock()
	if _, exists := s.entries[entry.Tuple]; !exists {
		ct.count.Add(1)
	}
	s.entries[entry.Tuple] = entry
	s.mu.Unlock()
}

// Update applies fn to the entry identified by tuple while holding
// the shard write lock. fn is not called if the entry does not exist.
func (ct *ConnTrack) Update(tuple FiveTuple, fn func(*ConnEntry)) {
	s := ct.shard(tuple)
	s.mu.Lock()
	if entry, ok := s.entries[tuple]; ok {
		fn(entry)
	}
	s.mu.Unlock()
}

// Delete removes a connection entry from the tracking table.
func (ct *ConnTrack) Delete(tuple FiveTuple) {
	s := ct.shard(tuple)
	s.mu.Lock()
	if _, ok := s.entries[tuple]; ok {
		delete(s.entries, tuple)
		ct.count.Add(-1)
	}
	s.mu.Unlock()
}

// Count returns the number of tracked connections across all shards.
func (ct *ConnTrack) Count() int {
	return int(ct.count.Load())
}

// Expire removes all entries whose LastSeen time plus the applicable
// timeout has passed. It returns the number of entries removed.
func (ct *ConnTrack) Expire(now time.Time) int {
	removed := 0
	for i := range ct.shards {
		s := &ct.shards[i]
		s.mu.Lock()
		for tuple, entry := range s.entries {
			timeout := ct.timeoutFor(entry)
			if now.Sub(entry.LastSeen) > timeout {
				delete(s.entries, tuple)
				removed++
			}
		}
		s.mu.Unlock()
	}
	ct.count.Add(-int64(removed))
	return removed
}

// timeoutFor returns the applicable timeout duration for a connection entry.
func (ct *ConnTrack) timeoutFor(entry *ConnEntry) time.Duration {
	switch entry.Tuple.Protocol {
	case ProtocolTCP:
		if entry.State == ConnStateEstablished {
			return ct.timeout.TCPEstablished
		}
		return ct.timeout.TCPClose
	case ProtocolUDP:
		return ct.timeout.UDP
	case ProtocolICMP:
		return ct.timeout.ICMP
	default:
		return ct.timeout.UDP
	}
}

// Snapshot returns a copy of all connection entries across all shards.
// This is intended for replication and is not allocation-free.
func (ct *ConnTrack) Snapshot() []*ConnEntry {
	total := ct.Count()
	if total == 0 {
		return nil
	}
	entries := make([]*ConnEntry, 0, total)
	for i := range ct.shards {
		s := &ct.shards[i]
		s.mu.RLock()
		for _, entry := range s.entries {
			cp := *entry
			if entry.NATInfo != nil {
				natCopy := *entry.NATInfo
				cp.NATInfo = &natCopy
			}
			entries = append(entries, &cp)
		}
		s.mu.RUnlock()
	}
	return entries
}

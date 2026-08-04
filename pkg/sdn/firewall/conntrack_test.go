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
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testTuple(srcPort, dstPort uint16) FiveTuple {
	return FiveTuple{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: ProtocolTCP,
	}
}

func TestConnTrack_InsertAndLookup(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()
	tuple := testTuple(12345, 80)
	entry := &ConnEntry{
		Tuple:    tuple,
		State:    ConnStateNew,
		Created:  now,
		LastSeen: now,
		Packets:  1,
		Bytes:    64,
	}

	ct.Insert(entry)

	got, ok := ct.Lookup(tuple)
	if !ok {
		t.Fatal("expected to find inserted entry")
	}
	if got.Tuple != tuple {
		t.Errorf("tuple mismatch: got %+v, want %+v", got.Tuple, tuple)
	}
	if got.Packets != 1 {
		t.Errorf("packets: got %d, want 1", got.Packets)
	}
	if ct.Count() != 1 {
		t.Errorf("count: got %d, want 1", ct.Count())
	}
}

func TestConnTrack_LookupMiss(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	tuple := testTuple(12345, 80)

	_, ok := ct.Lookup(tuple)
	if ok {
		t.Fatal("expected lookup miss for empty table")
	}
}

func TestConnTrack_Update(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()
	tuple := testTuple(12345, 80)
	ct.Insert(&ConnEntry{
		Tuple:    tuple,
		State:    ConnStateNew,
		Created:  now,
		LastSeen: now,
		Packets:  1,
		Bytes:    64,
	})

	ct.Update(tuple, func(ce *ConnEntry) {
		ce.State = ConnStateEstablished
		ce.Packets = 10
		ce.Bytes = 640
	})

	got, ok := ct.Lookup(tuple)
	if !ok {
		t.Fatal("expected entry after update")
	}
	if got.State != ConnStateEstablished {
		t.Errorf("state: got %v, want ESTABLISHED", got.State)
	}
	if got.Packets != 10 {
		t.Errorf("packets: got %d, want 10", got.Packets)
	}
}

func TestConnTrack_UpdateMiss(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	tuple := testTuple(12345, 80)

	// Should not panic on missing entry.
	ct.Update(tuple, func(ce *ConnEntry) {
		ce.Packets = 999
	})

	if ct.Count() != 0 {
		t.Errorf("count: got %d, want 0", ct.Count())
	}
}

func TestConnTrack_Delete(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()
	tuple := testTuple(12345, 80)
	ct.Insert(&ConnEntry{
		Tuple:    tuple,
		State:    ConnStateNew,
		Created:  now,
		LastSeen: now,
	})

	ct.Delete(tuple)

	_, ok := ct.Lookup(tuple)
	if ok {
		t.Fatal("expected entry to be deleted")
	}
	if ct.Count() != 0 {
		t.Errorf("count after delete: got %d, want 0", ct.Count())
	}
}

func TestConnTrack_DeleteMiss(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	tuple := testTuple(12345, 80)

	// Should not panic on missing entry.
	ct.Delete(tuple)

	if ct.Count() != 0 {
		t.Errorf("count: got %d, want 0", ct.Count())
	}
}

func TestConnTrack_InsertOverwrite(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()
	tuple := testTuple(12345, 80)

	ct.Insert(&ConnEntry{
		Tuple:    tuple,
		State:    ConnStateNew,
		Created:  now,
		LastSeen: now,
		Packets:  1,
	})
	ct.Insert(&ConnEntry{
		Tuple:    tuple,
		State:    ConnStateEstablished,
		Created:  now,
		LastSeen: now,
		Packets:  5,
	})

	if ct.Count() != 1 {
		t.Errorf("count after overwrite: got %d, want 1", ct.Count())
	}
	got, ok := ct.Lookup(tuple)
	if !ok {
		t.Fatal("expected entry")
	}
	if got.State != ConnStateEstablished {
		t.Errorf("state: got %v, want ESTABLISHED", got.State)
	}
}

func TestConnTrack_Expire(t *testing.T) {
	timeouts := ConnTrackTimeouts{
		TCPEstablished: 100 * time.Millisecond,
		TCPClose:       50 * time.Millisecond,
		UDP:            50 * time.Millisecond,
		ICMP:           50 * time.Millisecond,
	}
	ct := NewConnTrack(timeouts, testLogger())

	past := time.Now().Add(-200 * time.Millisecond)
	ct.Insert(&ConnEntry{
		Tuple:    testTuple(1, 80),
		State:    ConnStateEstablished,
		Created:  past,
		LastSeen: past,
	})
	ct.Insert(&ConnEntry{
		Tuple: FiveTuple{
			SrcIP:    netip.MustParseAddr("10.0.0.1"),
			DstIP:    netip.MustParseAddr("10.0.0.2"),
			SrcPort:  2,
			DstPort:  53,
			Protocol: ProtocolUDP,
		},
		State:    ConnStateNew,
		Created:  past,
		LastSeen: past,
	})

	// Fresh entry should not be expired.
	now := time.Now()
	ct.Insert(&ConnEntry{
		Tuple:    testTuple(3, 443),
		State:    ConnStateEstablished,
		Created:  now,
		LastSeen: now,
	})

	removed := ct.Expire(time.Now())
	if removed != 2 {
		t.Errorf("expired: got %d, want 2", removed)
	}
	if ct.Count() != 1 {
		t.Errorf("remaining: got %d, want 1", ct.Count())
	}
}

func TestConnTrack_ExpireEmpty(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	removed := ct.Expire(time.Now())
	if removed != 0 {
		t.Errorf("expired from empty table: got %d, want 0", removed)
	}
}

func TestConnTrack_Snapshot(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()

	for i := uint16(0); i < 10; i++ {
		ct.Insert(&ConnEntry{
			Tuple:    testTuple(i+1000, 80),
			State:    ConnStateNew,
			Created:  now,
			LastSeen: now,
			NATInfo: &NATEntry{
				Type: NATTypeSNAT,
			},
		})
	}

	snap := ct.Snapshot()
	if len(snap) != 10 {
		t.Errorf("snapshot length: got %d, want 10", len(snap))
	}

	// Verify snapshot is a deep copy by modifying it.
	if len(snap) > 0 {
		snap[0].Packets = 9999
		snap[0].NATInfo.Type = NATTypeDNAT
		orig, ok := ct.Lookup(snap[0].Tuple)
		if !ok {
			t.Fatal("expected to find original entry")
		}
		if orig.Packets == 9999 {
			t.Error("snapshot modification leaked to original")
		}
		if orig.NATInfo != nil && orig.NATInfo.Type == NATTypeDNAT {
			t.Error("snapshot NAT modification leaked to original")
		}
	}
}

func TestConnTrack_SnapshotEmpty(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	snap := ct.Snapshot()
	if snap != nil {
		t.Errorf("snapshot of empty table: got %v, want nil", snap)
	}
}

func TestConnTrack_ConcurrentAccess(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()
	const workers = 16
	const opsPerWorker = 1000

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			base := uint16(id * opsPerWorker)
			for i := uint16(0); i < opsPerWorker; i++ {
				tuple := testTuple(base+i, 80)
				ct.Insert(&ConnEntry{
					Tuple:    tuple,
					State:    ConnStateNew,
					Created:  now,
					LastSeen: now,
				})
				ct.Lookup(tuple)
				ct.Update(tuple, func(ce *ConnEntry) {
					ce.Packets++
				})
			}
		}(w)
	}
	wg.Wait()

	if ct.Count() != workers*opsPerWorker {
		t.Errorf("count: got %d, want %d", ct.Count(), workers*opsPerWorker)
	}
}

func TestConnTrack_ShardDistribution(t *testing.T) {
	ct := NewConnTrack(DefaultTimeouts(), testLogger())
	now := time.Now()
	const entries = 10000

	for i := uint16(0); i < entries; i++ {
		ct.Insert(&ConnEntry{
			Tuple: FiveTuple{
				SrcIP:    netip.MustParseAddr("10.0.0.1"),
				DstIP:    netip.MustParseAddr("10.0.0.2"),
				SrcPort:  i + 1024,
				DstPort:  80,
				Protocol: ProtocolTCP,
			},
			State:    ConnStateNew,
			Created:  now,
			LastSeen: now,
		})
	}

	// Verify entries are distributed across shards (not all in one).
	nonEmpty := 0
	for i := range ct.shards {
		ct.shards[i].mu.RLock()
		if len(ct.shards[i].entries) > 0 {
			nonEmpty++
		}
		ct.shards[i].mu.RUnlock()
	}

	// With 10K entries across 256 shards, we expect most shards populated.
	// A minimum of 50 non-empty shards is a reasonable threshold.
	if nonEmpty < 50 {
		t.Errorf("poor shard distribution: only %d of %d shards non-empty with %d entries",
			nonEmpty, connTrackShardCount, entries)
	}
}

func TestConnState_String(t *testing.T) {
	tests := []struct {
		state ConnState
		want  string
	}{
		{ConnStateNew, "NEW"},
		{ConnStateEstablished, "ESTABLISHED"},
		{ConnStateRelated, "RELATED"},
		{ConnStateInvalid, "INVALID"},
		{ConnState(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("ConnState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestFiveTuple_HashConsistency(t *testing.T) {
	tuple := testTuple(12345, 80)
	h1 := tuple.hash()
	h2 := tuple.hash()
	if h1 != h2 {
		t.Errorf("hash not deterministic: %d != %d", h1, h2)
	}
}

func TestFiveTuple_HashIPv6(t *testing.T) {
	tuple := FiveTuple{
		SrcIP:    netip.MustParseAddr("2001:db8::1"),
		DstIP:    netip.MustParseAddr("2001:db8::2"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}
	h1 := tuple.hash()
	h2 := tuple.hash()
	if h1 != h2 {
		t.Errorf("IPv6 hash not deterministic: %d != %d", h1, h2)
	}

	// Different tuple should produce different hash.
	tuple2 := FiveTuple{
		SrcIP:    netip.MustParseAddr("2001:db8::3"),
		DstIP:    netip.MustParseAddr("2001:db8::4"),
		SrcPort:  12345,
		DstPort:  443,
		Protocol: ProtocolTCP,
	}
	if tuple.hash() == tuple2.hash() {
		t.Error("different IPv6 tuples produced same hash")
	}
}

func TestConnTrack_DefaultTimeouts(t *testing.T) {
	ct := NewConnTrack(ConnTrackTimeouts{}, testLogger())
	defaults := DefaultTimeouts()
	if ct.timeout.TCPEstablished != defaults.TCPEstablished {
		t.Errorf("TCPEstablished: got %v, want %v", ct.timeout.TCPEstablished, defaults.TCPEstablished)
	}
	if ct.timeout.TCPClose != defaults.TCPClose {
		t.Errorf("TCPClose: got %v, want %v", ct.timeout.TCPClose, defaults.TCPClose)
	}
	if ct.timeout.UDP != defaults.UDP {
		t.Errorf("UDP: got %v, want %v", ct.timeout.UDP, defaults.UDP)
	}
	if ct.timeout.ICMP != defaults.ICMP {
		t.Errorf("ICMP: got %v, want %v", ct.timeout.ICMP, defaults.ICMP)
	}
}

func TestConnTrack_TimeoutFor(t *testing.T) {
	timeouts := ConnTrackTimeouts{
		TCPEstablished: 5 * time.Minute,
		TCPClose:       30 * time.Second,
		UDP:            45 * time.Second,
		ICMP:           20 * time.Second,
	}
	ct := NewConnTrack(timeouts, testLogger())

	tests := []struct {
		name     string
		entry    *ConnEntry
		expected time.Duration
	}{
		{
			name: "tcp established",
			entry: &ConnEntry{
				Tuple: FiveTuple{Protocol: ProtocolTCP},
				State: ConnStateEstablished,
			},
			expected: 5 * time.Minute,
		},
		{
			name: "tcp new",
			entry: &ConnEntry{
				Tuple: FiveTuple{Protocol: ProtocolTCP},
				State: ConnStateNew,
			},
			expected: 30 * time.Second,
		},
		{
			name: "udp",
			entry: &ConnEntry{
				Tuple: FiveTuple{Protocol: ProtocolUDP},
				State: ConnStateNew,
			},
			expected: 45 * time.Second,
		},
		{
			name: "icmp",
			entry: &ConnEntry{
				Tuple: FiveTuple{Protocol: ProtocolICMP},
				State: ConnStateNew,
			},
			expected: 20 * time.Second,
		},
		{
			name: "unknown protocol uses UDP timeout",
			entry: &ConnEntry{
				Tuple: FiveTuple{Protocol: 47},
				State: ConnStateNew,
			},
			expected: 45 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ct.timeoutFor(tt.entry)
			if got != tt.expected {
				t.Errorf("timeoutFor: got %v, want %v", got, tt.expected)
			}
		})
	}
}

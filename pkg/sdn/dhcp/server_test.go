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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStatsCollector(t *testing.T) {
	t.Run("creates new collector with zero values", func(t *testing.T) {
		s := NewStatsCollector()
		require.NotNil(t, s)

		stats := s.Snapshot()
		assert.True(t, stats.StartedAt.IsZero())
		assert.Equal(t, uint64(0), stats.PacketsReceived)
		assert.Equal(t, uint64(0), stats.PacketsSent)
		assert.Equal(t, uint64(0), stats.DiscoverCount)
		assert.Equal(t, uint64(0), stats.OfferCount)
		assert.Equal(t, uint64(0), stats.RequestCount)
		assert.Equal(t, uint64(0), stats.AckCount)
		assert.Equal(t, uint64(0), stats.NakCount)
		assert.Equal(t, uint64(0), stats.ReleaseCount)
		assert.Equal(t, uint64(0), stats.DeclineCount)
		assert.Equal(t, uint64(0), stats.InformCount)
		assert.Equal(t, uint64(0), stats.ErrorCount)
		assert.Equal(t, 0, stats.ActiveLeases)
	})
}

func TestStatsCollector_Start(t *testing.T) {
	t.Run("sets started time", func(t *testing.T) {
		s := NewStatsCollector()
		before := time.Now()
		s.Start()
		after := time.Now()

		stats := s.Snapshot()
		assert.False(t, stats.StartedAt.IsZero())
		assert.True(t, stats.StartedAt.After(before) || stats.StartedAt.Equal(before))
		assert.True(t, stats.StartedAt.Before(after) || stats.StartedAt.Equal(after))
	})
}

func TestStatsCollector_Reset(t *testing.T) {
	t.Run("resets all counters", func(t *testing.T) {
		s := NewStatsCollector()
		s.Start()
		s.IncPacketsReceived()
		s.IncPacketsSent()
		s.IncDiscover()
		s.IncOffer()
		s.IncRequest()
		s.IncAck()
		s.IncNak()
		s.IncRelease()
		s.IncDecline()
		s.IncInform()
		s.IncError()
		s.SetActiveLeases(10)

		s.Reset()

		stats := s.Snapshot()
		assert.True(t, stats.StartedAt.IsZero())
		assert.Equal(t, uint64(0), stats.PacketsReceived)
		assert.Equal(t, uint64(0), stats.PacketsSent)
		assert.Equal(t, uint64(0), stats.DiscoverCount)
		assert.Equal(t, uint64(0), stats.OfferCount)
		assert.Equal(t, uint64(0), stats.RequestCount)
		assert.Equal(t, uint64(0), stats.AckCount)
		assert.Equal(t, uint64(0), stats.NakCount)
		assert.Equal(t, uint64(0), stats.ReleaseCount)
		assert.Equal(t, uint64(0), stats.DeclineCount)
		assert.Equal(t, uint64(0), stats.InformCount)
		assert.Equal(t, uint64(0), stats.ErrorCount)
		assert.Equal(t, 0, stats.ActiveLeases)
	})
}

func TestStatsCollector_IncPacketsReceived(t *testing.T) {
	t.Run("increments packets received", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncPacketsReceived()
		s.IncPacketsReceived()
		s.IncPacketsReceived()

		stats := s.Snapshot()
		assert.Equal(t, uint64(3), stats.PacketsReceived)
	})
}

func TestStatsCollector_IncPacketsSent(t *testing.T) {
	t.Run("increments packets sent", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncPacketsSent()
		s.IncPacketsSent()

		stats := s.Snapshot()
		assert.Equal(t, uint64(2), stats.PacketsSent)
	})
}

func TestStatsCollector_IncDiscover(t *testing.T) {
	t.Run("increments discover count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncDiscover()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.DiscoverCount)
	})
}

func TestStatsCollector_IncOffer(t *testing.T) {
	t.Run("increments offer count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncOffer()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.OfferCount)
	})
}

func TestStatsCollector_IncRequest(t *testing.T) {
	t.Run("increments request count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncRequest()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.RequestCount)
	})
}

func TestStatsCollector_IncAck(t *testing.T) {
	t.Run("increments ack count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncAck()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.AckCount)
	})
}

func TestStatsCollector_IncNak(t *testing.T) {
	t.Run("increments nak count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncNak()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.NakCount)
	})
}

func TestStatsCollector_IncRelease(t *testing.T) {
	t.Run("increments release count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncRelease()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.ReleaseCount)
	})
}

func TestStatsCollector_IncDecline(t *testing.T) {
	t.Run("increments decline count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncDecline()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.DeclineCount)
	})
}

func TestStatsCollector_IncInform(t *testing.T) {
	t.Run("increments inform count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncInform()

		stats := s.Snapshot()
		assert.Equal(t, uint64(1), stats.InformCount)
	})
}

func TestStatsCollector_IncError(t *testing.T) {
	t.Run("increments error count", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncError()
		s.IncError()

		stats := s.Snapshot()
		assert.Equal(t, uint64(2), stats.ErrorCount)
	})
}

func TestStatsCollector_SetActiveLeases(t *testing.T) {
	t.Run("sets active leases count", func(t *testing.T) {
		s := NewStatsCollector()
		s.SetActiveLeases(50)

		stats := s.Snapshot()
		assert.Equal(t, 50, stats.ActiveLeases)
	})

	t.Run("overwrites previous value", func(t *testing.T) {
		s := NewStatsCollector()
		s.SetActiveLeases(100)
		s.SetActiveLeases(25)

		stats := s.Snapshot()
		assert.Equal(t, 25, stats.ActiveLeases)
	})
}

func TestStatsCollector_IncActiveLeases(t *testing.T) {
	t.Run("increments active leases", func(t *testing.T) {
		s := NewStatsCollector()
		s.IncActiveLeases()
		s.IncActiveLeases()
		s.IncActiveLeases()

		stats := s.Snapshot()
		assert.Equal(t, 3, stats.ActiveLeases)
	})
}

func TestStatsCollector_DecActiveLeases(t *testing.T) {
	t.Run("decrements active leases", func(t *testing.T) {
		s := NewStatsCollector()
		s.SetActiveLeases(10)
		s.DecActiveLeases()
		s.DecActiveLeases()

		stats := s.Snapshot()
		assert.Equal(t, 8, stats.ActiveLeases)
	})

	t.Run("can go negative", func(t *testing.T) {
		s := NewStatsCollector()
		s.DecActiveLeases()

		stats := s.Snapshot()
		assert.Equal(t, -1, stats.ActiveLeases)
	})
}

func TestStatsCollector_Snapshot(t *testing.T) {
	t.Run("returns copy of current stats", func(t *testing.T) {
		s := NewStatsCollector()
		s.Start()
		s.IncPacketsReceived()
		s.IncPacketsSent()
		s.IncDiscover()
		s.IncOffer()
		s.IncRequest()
		s.IncAck()
		s.IncNak()
		s.IncRelease()
		s.IncDecline()
		s.IncInform()
		s.IncError()
		s.SetActiveLeases(5)

		stats := s.Snapshot()

		assert.False(t, stats.StartedAt.IsZero())
		assert.Equal(t, uint64(1), stats.PacketsReceived)
		assert.Equal(t, uint64(1), stats.PacketsSent)
		assert.Equal(t, uint64(1), stats.DiscoverCount)
		assert.Equal(t, uint64(1), stats.OfferCount)
		assert.Equal(t, uint64(1), stats.RequestCount)
		assert.Equal(t, uint64(1), stats.AckCount)
		assert.Equal(t, uint64(1), stats.NakCount)
		assert.Equal(t, uint64(1), stats.ReleaseCount)
		assert.Equal(t, uint64(1), stats.DeclineCount)
		assert.Equal(t, uint64(1), stats.InformCount)
		assert.Equal(t, uint64(1), stats.ErrorCount)
		assert.Equal(t, 5, stats.ActiveLeases)
	})
}

func TestStatsCollector_Concurrency(t *testing.T) {
	t.Run("is safe for concurrent access", func(t *testing.T) {
		s := NewStatsCollector()
		s.Start()

		var wg sync.WaitGroup
		numGoroutines := 100
		numOps := 1000

		// Spawn goroutines that increment counters
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < numOps; j++ {
					s.IncPacketsReceived()
					s.IncPacketsSent()
					s.IncDiscover()
					s.IncOffer()
					s.IncRequest()
					s.IncAck()
					s.IncNak()
					s.IncRelease()
					s.IncDecline()
					s.IncInform()
					s.IncError()
					s.IncActiveLeases()
					s.DecActiveLeases()
					_ = s.Snapshot()
				}
			}()
		}

		wg.Wait()

		stats := s.Snapshot()
		expected := uint64(numGoroutines * numOps)

		assert.Equal(t, expected, stats.PacketsReceived)
		assert.Equal(t, expected, stats.PacketsSent)
		assert.Equal(t, expected, stats.DiscoverCount)
		assert.Equal(t, expected, stats.OfferCount)
		assert.Equal(t, expected, stats.RequestCount)
		assert.Equal(t, expected, stats.AckCount)
		assert.Equal(t, expected, stats.NakCount)
		assert.Equal(t, expected, stats.ReleaseCount)
		assert.Equal(t, expected, stats.DeclineCount)
		assert.Equal(t, expected, stats.InformCount)
		assert.Equal(t, expected, stats.ErrorCount)
		assert.Equal(t, 0, stats.ActiveLeases) // Inc and Dec cancel out
	})
}

func TestMessageType_String(t *testing.T) {
	tests := []struct {
		msgType  MessageType
		expected string
	}{
		{MessageTypeDiscover, "DISCOVER"},
		{MessageTypeOffer, "OFFER"},
		{MessageTypeRequest, "REQUEST"},
		{MessageTypeDecline, "DECLINE"},
		{MessageTypeAck, "ACK"},
		{MessageTypeNak, "NAK"},
		{MessageTypeRelease, "RELEASE"},
		{MessageTypeInform, "INFORM"},
		{MessageType(0), "UNKNOWN"},
		{MessageType(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.msgType.String())
		})
	}
}

func TestMessageType_IsValid(t *testing.T) {
	t.Run("valid message types", func(t *testing.T) {
		assert.True(t, MessageTypeDiscover.IsValid())
		assert.True(t, MessageTypeOffer.IsValid())
		assert.True(t, MessageTypeRequest.IsValid())
		assert.True(t, MessageTypeDecline.IsValid())
		assert.True(t, MessageTypeAck.IsValid())
		assert.True(t, MessageTypeNak.IsValid())
		assert.True(t, MessageTypeRelease.IsValid())
		assert.True(t, MessageTypeInform.IsValid())
	})

	t.Run("invalid message types", func(t *testing.T) {
		assert.False(t, MessageType(0).IsValid())
		assert.False(t, MessageType(9).IsValid())
		assert.False(t, MessageType(255).IsValid())
	})
}

func TestMessageTypeConstants(t *testing.T) {
	// Verify message type values match RFC 2132
	assert.Equal(t, MessageType(1), MessageTypeDiscover)
	assert.Equal(t, MessageType(2), MessageTypeOffer)
	assert.Equal(t, MessageType(3), MessageTypeRequest)
	assert.Equal(t, MessageType(4), MessageTypeDecline)
	assert.Equal(t, MessageType(5), MessageTypeAck)
	assert.Equal(t, MessageType(6), MessageTypeNak)
	assert.Equal(t, MessageType(7), MessageTypeRelease)
	assert.Equal(t, MessageType(8), MessageTypeInform)
}

func TestMessageTypeStrings(t *testing.T) {
	// Verify map contains all message types
	assert.Equal(t, 8, len(messageTypeStrings))

	for msgType, str := range messageTypeStrings {
		assert.True(t, msgType.IsValid())
		assert.NotEmpty(t, str)
		assert.Equal(t, str, msgType.String())
	}
}

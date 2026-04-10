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
	"log/slog"
	"os"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecordResponseStats_AllTypes verifies that recordResponseStats
// correctly increments counters for all supported response types.
func TestRecordResponseStats_AllTypes(t *testing.T) {
	s := &CoreDHCPServer{
		stats: NewStatsCollector(),
	}

	s.recordResponseStats(dhcpv4.MessageTypeOffer)
	s.recordResponseStats(dhcpv4.MessageTypeAck)
	s.recordResponseStats(dhcpv4.MessageTypeNak)

	stats := s.stats.Snapshot()
	assert.Equal(t, uint64(1), stats.OfferCount)
	assert.Equal(t, uint64(1), stats.AckCount)
	assert.Equal(t, uint64(1), stats.NakCount)
}

// TestRecordResponseStats_UnknownType verifies that unknown response types
// do not cause a panic or increment any counter.
func TestRecordResponseStats_UnknownType(t *testing.T) {
	s := &CoreDHCPServer{
		stats: NewStatsCollector(),
	}

	s.recordResponseStats(dhcpv4.MessageTypeDiscover)

	stats := s.stats.Snapshot()
	assert.Equal(t, uint64(0), stats.OfferCount)
	assert.Equal(t, uint64(0), stats.AckCount)
	assert.Equal(t, uint64(0), stats.NakCount)
}

// TestRecordMessageTypeStats_MultipleIncrements verifies counters accumulate.
func TestRecordMessageTypeStats_MultipleIncrements(t *testing.T) {
	s := &CoreDHCPServer{
		stats: NewStatsCollector(),
	}

	for i := 0; i < 5; i++ {
		s.recordMessageTypeStats(dhcpv4.MessageTypeDiscover)
	}
	for i := 0; i < 3; i++ {
		s.recordMessageTypeStats(dhcpv4.MessageTypeRequest)
	}

	stats := s.stats.Snapshot()
	assert.Equal(t, uint64(5), stats.DiscoverCount)
	assert.Equal(t, uint64(3), stats.RequestCount)
}

// TestCoreDHCPServer_Stop_Running verifies Stop works on a server in running
// state, exercising stopAllServersLocked with cancel funcs and plugins.
func TestCoreDHCPServer_Stop_Running(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	srv := &CoreDHCPServer{
		config:      &ServerConfig{},
		stats:       NewStatsCollector(),
		logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		servers:     make(map[string]*server4.Server),
		plugins:     make(map[string]*IPAMPlugin),
		cancelFuncs: map[string]context.CancelFunc{"eth0": cancel},
	}
	srv.running.Store(true)

	err := srv.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, srv.running.Load())
	assert.Empty(t, srv.cancelFuncs)
}

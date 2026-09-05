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

package reporting

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_MissIsDistinguishableFromAFailedVerdict(t *testing.T) {
	c := NewCache(time.Hour)

	r, ok := c.Report("never-seen")
	assert.False(t, ok)
	assert.Nil(t, r,
		"a miss must return nil, not a zero Report — a zero Report has Verified=false "+
			"and reads as a device that failed attestation rather than one never collected")
}

func TestCache_StaleReportIsRetainedNotDiscarded(t *testing.T) {
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	c := newCacheWithClock(time.Hour, clk)

	c.Store(&Report{DeviceID: "dev-1", Verified: true, CollectedAt: clk.Now()})
	assert.True(t, c.Fresh("dev-1"))

	clk.advance(2 * time.Hour)

	assert.False(t, c.Fresh("dev-1"), "past the TTL the report is stale")
	r, ok := c.Report("dev-1")
	require.True(t, ok,
		"a stale report must still be readable: expiry means the evidence is old, "+
			"not that the device has none, and deleting it makes an overdue device "+
			"indistinguishable from a never-collected one")
	assert.True(t, r.Verified)
	assert.Equal(t, 2*time.Hour, r.Age(clk.Now()))
}

// TestCache_TTLDefaultExceedsTheRefreshInterval guards a budget that cannot
// be satisfied by correct behaviour: a TTL shorter than the refresh cycle
// marks every report stale before its replacement is due, so a perfectly
// healthy fleet reports nothing fresh.
func TestCache_TTLDefaultExceedsTheRefreshInterval(t *testing.T) {
	assert.Greater(t, DefaultTTL, DefaultInterval,
		"the freshness window must outlast the refresh cycle, or every report is "+
			"stale before the collector is due to replace it")
}

func TestCache_ZeroTTLUsesTheDefault(t *testing.T) {
	assert.Equal(t, DefaultTTL, NewCache(0).TTL())
	assert.Equal(t, DefaultTTL, NewCache(-time.Second).TTL())
}

func TestCache_StoreIgnoresUnusableReports(t *testing.T) {
	c := NewCache(time.Hour)
	c.Store(nil)
	c.Store(&Report{DeviceID: ""})
	assert.Zero(t, c.Len(), "a report with no device id has nothing to be the report OF")
}

func TestCache_ReportsIsOrderedForAStableFleetView(t *testing.T) {
	c := NewCache(time.Hour)
	for _, id := range []string{"dev-3", "dev-1", "dev-2"} {
		c.Store(&Report{DeviceID: id})
	}
	got := make([]string, 0, 3)
	for _, r := range c.Reports() {
		got = append(got, r.DeviceID)
	}
	assert.Equal(t, []string{"dev-1", "dev-2", "dev-3"}, got,
		"map iteration order would reshuffle a fleet table between refreshes")
}

func TestCache_ForgetDropsADeviceLeavingTheFleet(t *testing.T) {
	c := NewCache(time.Hour)
	c.Store(&Report{DeviceID: "dev-1"})
	require.Equal(t, 1, c.Len())
	c.Forget("dev-1")
	_, ok := c.Report("dev-1")
	assert.False(t, ok)
}

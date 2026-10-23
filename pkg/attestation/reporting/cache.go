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
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Cache holds the most recent verified report per device.
//
// It is the ONLY thing a request handler touches. The cache has no reference
// to a QuoteSource, no reference to a Verifier, and no method that blocks —
// so no code path from a handler through this type can reach a device. That
// is the never-quote-on-request invariant expressed as a type rather than as
// a comment.
//
// A report is retained past its TTL rather than discarded. Expiry means "this
// evidence is stale", not "this device has no evidence": deleting it would
// turn a device whose collection is merely overdue into one indistinguishable
// from a device never collected, and absence of evidence is not failed
// attestation. Consumers read Fresh alongside the report and decide.
type Cache struct {
	mu      sync.RWMutex
	reports map[string]*Report
	ttl     time.Duration
	clk     clock

	// store, when set by Persist, receives every stored report. It can
	// only write reports out; it has no path to a device.
	store  Store
	logger *slog.Logger
}

// NewCache returns a cache holding reports for ttl before they are considered
// stale. A non-positive ttl uses DefaultTTL.
func NewCache(ttl time.Duration) *Cache {
	return newCacheWithClock(ttl, realClock{})
}

func newCacheWithClock(ttl time.Duration, clk clock) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{
		reports: make(map[string]*Report),
		ttl:     ttl,
		clk:     clk,
	}
}

// TTL returns the configured freshness window.
func (c *Cache) TTL() time.Duration { return c.ttl }

// Report returns the most recent report for a device.
//
// A device with no report returns (nil, false). It does NOT return a
// zero-valued Report: a caller must be able to distinguish "never collected"
// from "collected and failed", and a synthesised empty report reads as the
// second.
func (c *Cache) Report(deviceID string) (*Report, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.reports[deviceID]
	if !ok {
		return nil, false
	}
	return r, true
}

// Reports returns every cached report, ordered by device id so the fleet view
// is stable between calls.
func (c *Cache) Reports() []*Report {
	c.mu.RLock()
	out := make([]*Report, 0, len(c.reports))
	for _, r := range c.reports {
		out = append(out, r)
	}
	c.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// Fresh reports whether a device has a report still inside the TTL.
func (c *Cache) Fresh(deviceID string) bool {
	r, ok := c.Report(deviceID)
	if !ok {
		return false
	}
	return c.IsFresh(r)
}

// IsFresh reports whether a report is inside the TTL as of now.
func (c *Cache) IsFresh(r *Report) bool {
	if r == nil {
		return false
	}
	return r.Age(c.clk.Now()) < c.ttl
}

// Now returns the cache's view of the current instant, so a consumer can
// render a report's age with the same clock that judged its freshness.
func (c *Cache) Now() time.Time { return c.clk.Now() }

// Store records a report as the current one for its device.
//
// The whole report is replaced in a single map assignment. That matters: a
// report is written in one operation and read in one operation, so there is
// no window in which a reader can observe a half-updated verdict — a device
// showing its new signature result beside its old PCR result would be a
// verdict that never existed. A partial write here leaves the PREVIOUS report
// intact, which is the correct failure: stale and true beats fresh and
// incoherent.
//
// A report never replaces one from a later verification: the collector's
// report and a verdict recorded from another path (OnDeviceVerdict) can race,
// and the older one must not win. Reports of the same verification carry the
// same AttestedAt, so the collector's full report still replaces the one
// derived from its own verdict.
func (c *Cache) Store(r *Report) {
	if r == nil || r.DeviceID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeLocked(r)
}

// storeLocked records r unless the held report is from a later verification.
// The caller holds c.mu.
func (c *Cache) storeLocked(r *Report) {
	if held := c.reports[r.DeviceID]; held != nil && held.AttestedAt.After(r.AttestedAt) {
		return
	}
	c.reports[r.DeviceID] = r
	c.persist(r)
}

// Forget drops a device's report, for a device leaving the fleet.
func (c *Cache) Forget(deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.reports, deviceID)
}

// Len returns the number of devices with a report.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.reports)
}

// Cache is the production Reader.
var _ Reader = (*Cache)(nil)

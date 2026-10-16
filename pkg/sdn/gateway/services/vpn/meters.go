// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vpn

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// reattestBuckets are the upper bounds, in seconds, of the re-attestation
// duration histogram: a local quote verification takes milliseconds, a
// verifier under load or across the network seconds.
var reattestBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// maxPostureRuleLabels bounds the distinct posture rule names counted by
// name. The names come from tenant policies; past the bound a violation is
// counted under OtherPostureRule, so a policy that mints rule names cannot
// grow the gateway's metrics without limit.
const maxPostureRuleLabels = 64

// OtherPostureRule is the label a posture violation is counted under once
// maxPostureRuleLabels distinct rule names have been seen.
const OtherPostureRule = "other"

// DurationHistogram is a cumulative histogram of durations, in the shape a
// Prometheus histogram exports.
type DurationHistogram struct {
	Count uint64
	Sum   time.Duration
	// Buckets are cumulative: each counts the observations at or under its
	// upper bound. Observations over the last bound count only in Count.
	Buckets []HistogramBucket
}

// HistogramBucket is one cumulative histogram bucket.
type HistogramBucket struct {
	UpperBoundSeconds float64
	Count             uint64
}

// durationHistogram records durations without a lock.
type durationHistogram struct {
	bounds []float64
	// counts holds one count per bucket, not cumulative; the extra last
	// slot counts the observations over every bound.
	counts []atomic.Uint64
	sum    atomic.Int64
}

func newDurationHistogram(bounds []float64) *durationHistogram {
	return &durationHistogram{bounds: bounds, counts: make([]atomic.Uint64, len(bounds)+1)}
}

// observe records one duration; a negative one (a clock stepped back) counts
// as zero.
func (h *durationHistogram) observe(d time.Duration) {
	d = max(d, 0)
	h.counts[sort.SearchFloat64s(h.bounds, d.Seconds())].Add(1)
	h.sum.Add(int64(d))
}

// snapshot returns the histogram so far. Count is the sum of the buckets, so
// it never disagrees with them under concurrent observations.
func (h *durationHistogram) snapshot() DurationHistogram {
	out := DurationHistogram{Buckets: make([]HistogramBucket, len(h.bounds))}
	var cumulative uint64
	for i, bound := range h.bounds {
		cumulative += h.counts[i].Load()
		out.Buckets[i] = HistogramBucket{UpperBoundSeconds: bound, Count: cumulative}
	}
	out.Count = cumulative + h.counts[len(h.bounds)].Load()
	out.Sum = time.Duration(h.sum.Load())
	return out
}

// labelledCounters counts events by label, without a lock once a label has
// been seen. A positive limit bounds the distinct labels; an event past it
// counts under overflow.
type labelledCounters struct {
	limit    int64
	overflow string
	size     atomic.Int64
	counters sync.Map // string -> *atomic.Uint64
}

func (c *labelledCounters) inc(label string) {
	if n, ok := c.counters.Load(label); ok {
		addOne(n)
		return
	}
	if c.limit > 0 && c.size.Load() >= c.limit {
		label = c.overflow
	}
	n, loaded := c.counters.LoadOrStore(label, new(atomic.Uint64))
	if !loaded && label != c.overflow {
		c.size.Add(1)
	}
	addOne(n)
}

// snapshot returns the counts by label; nil when nothing was counted.
func (c *labelledCounters) snapshot() map[string]uint64 {
	var out map[string]uint64
	c.counters.Range(func(key, value any) bool {
		label, okLabel := key.(string)
		n, okCount := value.(*atomic.Uint64)
		if okLabel && okCount {
			if out == nil {
				out = make(map[string]uint64)
			}
			out[label] = n.Load()
		}
		return true
	})
	return out
}

// addOne increments a counter stored in a labelledCounters map.
func addOne(value any) {
	if n, ok := value.(*atomic.Uint64); ok {
		n.Add(1)
	}
}

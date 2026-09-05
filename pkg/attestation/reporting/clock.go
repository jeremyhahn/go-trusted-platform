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

import "time"

// clock is the collector's entire view of time.
//
// Two methods, matching the seam in pkg/security/ratelimit rather than the
// one-method `now func() time.Time` field used in pkg/ipxe, pkg/sdn/gateway/
// proxysvc and pkg/webservice/v1/adminclaim. The repo has both shapes and the
// distinction is not stylistic: a one-method seam is enough when production
// only READS time, and insufficient when it BLOCKS on it.
//
// This collector does both. It reads the clock to decide whether a cached
// report is still within its TTL, and it blocks between refresh cycles. A
// fake that controlled only Now would leave the loop waiting on the real
// clock for an interval that, in fake time, never elapses — so a test would
// either sleep or hang, and the no-sleep rule forbids the first.
//
// Unexported deliberately: this is a test seam, not a configuration knob.
// Production has exactly one implementation and the exported constructors do
// not mention it.
type clock interface {
	// Now returns the current instant. Reports carry a wall-clock collection
	// time that operators read, so this speaks time.Time rather than the
	// int64 nanos the rate limiter uses internally.
	Now() time.Time

	// After returns a channel that receives once d has elapsed, mirroring
	// time.After including its immediate fire on a non-positive d.
	After(d time.Duration) <-chan time.Time
}

// realClock is the production clock: the standard library, unmodified.
type realClock struct{}

// Now returns the current wall-clock time in UTC. UTC because a collection
// timestamp is compared against TTLs and rendered to operators in different
// places; a local-zone instant would compare correctly and display
// inconsistently.
func (realClock) Now() time.Time { return time.Now().UTC() }

// After returns time.After(d).
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

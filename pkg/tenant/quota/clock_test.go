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

package quota

import (
	"sync/atomic"
	"time"
)

// fakeQuotaClock is a clock the test moves by hand.
//
// Reservation expiry is a comparison against a stored instant, so with a
// controlled clock a test can sit exactly ON the boundary and one nanosecond
// past it. Sleeping cannot: it can only prove the reservation expired at some
// point at or before the sleep ended.
//
// It also removes a distortion the sleeps forced. Both converted tests used
// WithReservationTTL(1 * time.Millisecond) — a TTL chosen so the sleep could be
// short, not one resembling anything a tenant would be given. With time under
// the test's control the TTL can be production-realistic and the test still
// finishes instantly.
type fakeQuotaClock struct {
	nanos atomic.Int64
}

func newFakeQuotaClock() *fakeQuotaClock {
	c := &fakeQuotaClock{}
	c.nanos.Store(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *fakeQuotaClock) Now() time.Time { return time.Unix(0, c.nanos.Load()).UTC() }

func (c *fakeQuotaClock) Advance(d time.Duration) { c.nanos.Add(int64(d)) }

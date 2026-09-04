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

package ratelimit

import "time"

// clock is a rate limiter's entire view of time.
//
// Both limiters in this package are pure functions of elapsed time: a sliding
// window rotates when the window size has passed, a token bucket refills in
// proportion to the interval since the last draw. That makes "what time is it"
// the single input their behaviour turns on, and the only thing a test needs to
// control in order to drive them.
//
// The interface is deliberately two methods, because a limiter does exactly two
// things with time — it reads the current instant, and it waits for a computed
// interval before re-checking. Reading alone is not enough: WaitN blocks on the
// wait, so a fake that controlled only NowNano would leave WaitN waiting on the
// real clock for a deadline that, in fake time, never arrives.
//
// It is unexported on purpose. This is a test seam, not a configuration knob:
// production has exactly one implementation, callers have no reason to supply
// another, and the exported constructors do not mention it. That follows the
// onSweep observer already in this package — fixed at construction, nil or
// default in production, never mutated afterwards.
type clock interface {
	// NowNano returns the current time as Unix nanoseconds. Both limiters store
	// and compare instants as int64 nanos rather than time.Time, so the seam
	// speaks the representation the code already uses instead of forcing a
	// conversion at every call site.
	NowNano() int64

	// After returns a channel that receives once d has elapsed. It mirrors
	// time.After, including the guarantee that a non-positive d fires
	// immediately.
	After(d time.Duration) <-chan time.Time
}

// realClock is the production clock: the standard library, unmodified.
type realClock struct{}

// NowNano returns the wall-clock time in Unix nanoseconds.
func (realClock) NowNano() int64 { return time.Now().UnixNano() }

// After returns time.After(d).
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

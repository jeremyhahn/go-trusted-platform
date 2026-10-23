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

package testenv

import (
	"context"
	"time"
)

// WaitInterval is how often WaitUntil re-checks its condition.
const WaitInterval = 100 * time.Millisecond

// WaitTimeoutError reports a condition that did not hold before the wait
// ended. Err is the context error that ended it: context.DeadlineExceeded
// when the timeout ran out, context.Canceled when the caller gave up.
type WaitTimeoutError struct {
	Condition string
	Err       error
}

// Error implements the error interface.
func (e *WaitTimeoutError) Error() string {
	return "timed out waiting for " + e.Condition + ": " + e.Err.Error()
}

// Unwrap returns the context error that ended the wait.
func (e *WaitTimeoutError) Unwrap() error {
	return e.Err
}

// WaitUntil checks cond at once and then every WaitInterval until it holds,
// timeout elapses, or ctx ends. condition names what is awaited; it is the
// subject of the WaitTimeoutError returned when the wait ends unmet.
func WaitUntil(ctx context.Context, timeout time.Duration, condition string, cond func() bool) error {
	return WaitUntilEvery(ctx, timeout, WaitInterval, condition, cond)
}

// WaitUntilEvery is WaitUntil with its own poll interval, for conditions
// that are slow or costly to check (a ping, a TLS handshake).
func WaitUntilEvery(ctx context.Context, timeout, interval time.Duration, condition string, cond func() bool) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if cond() {
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return &WaitTimeoutError{Condition: condition, Err: ctx.Err()}
		case <-ticker.C:
			if cond() {
				return nil
			}
		}
	}
}

// WaitFor runs wait, a call that blocks until its condition holds (such as
// a process Wait), and returns its error. When timeout elapses or ctx ends
// first it returns a WaitTimeoutError naming condition; wait then finishes
// in the background and its result is dropped.
func WaitFor(ctx context.Context, timeout time.Duration, condition string, wait func() error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- wait()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return &WaitTimeoutError{Condition: condition, Err: ctx.Err()}
	}
}

// Elapse waits for d to pass, ending early with a WaitTimeoutError when ctx
// ends first. It is only for waits on real elapsed time, such as a boot
// budget, where nothing observable marks the end; every other wait polls
// its condition with WaitUntil.
func Elapse(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return &WaitTimeoutError{Condition: d.String() + " to elapse", Err: ctx.Err()}
	}
}

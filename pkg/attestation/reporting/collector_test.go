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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubLister struct{ ids []string }

func (l *stubLister) AttestableDevices(context.Context) ([]string, error) { return l.ids, nil }

// blockingSource holds each Collect until the test releases it, so
// concurrency can be arranged deterministically instead of by timing.
type blockingSource struct {
	entered chan string
	release chan struct{}
	calls   chan string
}

func newBlockingSource() *blockingSource {
	return &blockingSource{
		entered: make(chan string, 16),
		release: make(chan struct{}),
		calls:   make(chan string, 64),
	}
}

func (s *blockingSource) Collect(ctx context.Context, deviceID string, _ []byte) ([]byte, error) {
	s.entered <- deviceID
	s.calls <- deviceID
	select {
	case <-s.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []byte(`{"quote":"x"}`), nil
}

func (s *blockingSource) callCount() int { return len(s.calls) }

func testCollector(t *testing.T, cfg Config, clk clock) *Collector {
	t.Helper()
	if cfg.Verifier == nil {
		cfg.Verifier = &stubVerifier{report: &Report{Verified: true, Status: "verified"}}
	}
	c, err := newCollectorWithClock(cfg, clk)
	require.NoError(t, err)
	return c
}

// TestNewCollector_FailsClosedWithoutItsDependencies covers the error path:
// a collector missing a source or verifier must not construct. One that
// constructed would collect nothing, or store unverified evidence, while
// looking healthy.
func TestNewCollector_FailsClosedWithoutItsDependencies(t *testing.T) {
	_, err := NewCollector(Config{Verifier: &stubVerifier{}})
	require.Error(t, err)
	var noSource ErrNoQuoteSource
	assert.ErrorAs(t, err, &noSource)

	_, err = NewCollector(Config{Source: newCountingSource()})
	require.Error(t, err)
	var noVerifier ErrNoVerifier
	assert.ErrorAs(t, err, &noVerifier)
}

// TestCollector_RunRefreshesOnTheInterval drives the loop by advancing a
// fake clock — no sleeping, and no dependence on how fast the machine is.
func TestCollector_RunRefreshesOnTheInterval(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	c := testCollector(t, Config{
		Source:   src,
		Devices:  &stubLister{ids: []string{"dev-1", "dev-2"}},
		Interval: 15 * time.Minute,
	}, clk)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	// Run collects once at startup, so an empty cache is not left reporting
	// every device as never-collected for a full interval.
	waitFor(t, func() bool { return src.count() == 2 }, "startup collection")

	// The loop is now parked on the interval. Waiting for the timer to exist
	// before advancing is what makes this deterministic rather than a race.
	waitFor(t, func() bool { return clk.waiters_() > 0 }, "loop reached its wait")
	clk.advance(15 * time.Minute)
	waitFor(t, func() bool { return src.count() == 4 }, "second cycle")

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestCollector_ConcurrentCollectionsCoalescePerDevice is the TPM-protection
// test. Two concurrent refreshes of one device must produce ONE quote: the
// exhaustion this design prevents can arrive through overlapping requests
// just as easily as through repeated ones.
func TestCollector_ConcurrentCollectionsCoalescePerDevice(t *testing.T) {
	src := newBlockingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	c := testCollector(t, Config{Source: src, Interval: time.Minute}, clk)

	ctx := context.Background()
	first := make(chan struct{})
	second := make(chan struct{})
	go func() { c.Collect(ctx, "dev-1"); close(first) }()

	// Wait until the first collection is inside the source before starting
	// the second, so the overlap is arranged rather than hoped for.
	select {
	case <-src.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first collection never reached the source")
	}

	// Observe the coalesce directly rather than inferring it from timing.
	coalesced := make(chan string, 4)
	c.onCoalesce = func(id string) { coalesced <- id }

	go func() { c.Collect(ctx, "dev-1"); close(second) }()

	// The second call has now provably reached the coalesce point — no
	// waiting-and-hoping, and no second quote issued.
	select {
	case id := <-coalesced:
		assert.Equal(t, "dev-1", id)
	case <-time.After(5 * time.Second):
		t.Fatal("second collection never coalesced")
	}

	close(src.release)

	waitForClose(t, first, "first collection")
	waitForClose(t, second, "second collection")

	assert.Equal(t, 1, src.callCount(),
		"two concurrent refreshes of one device must produce ONE quote, not two")
}

// TestCollector_EnqueueGoesThroughTheCollector proves the operator path is on
// the collector rather than the reader, and that it is refused when the
// collector is not running rather than silently dropped.
func TestCollector_EnqueueGoesThroughTheCollector(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	c := testCollector(t, Config{Source: src, Interval: time.Hour}, clk)

	// Not running yet.
	err := c.Enqueue("dev-1")
	var stopped ErrCollectorStopped
	assert.ErrorAs(t, err, &stopped,
		"enqueueing against a stopped collector must fail loudly, not vanish")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	waitFor(t, func() bool { return clk.waiters_() > 0 }, "loop running")

	require.NoError(t, c.Enqueue("dev-1"))
	waitFor(t, func() bool { return src.count() >= 1 }, "enqueued collection ran")
}

// TestCollector_VerifierErrorIsNotAVerdict covers the other unevaluable
// case: evidence that could not be verified must leave the previous report
// alone, exactly as an unreachable device does.
func TestCollector_VerifierErrorIsNotAVerdict(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	verifier := &stubVerifier{report: &Report{Verified: true, Status: "verified"}}
	c := testCollector(t, Config{Source: src, Verifier: verifier, Interval: time.Minute}, clk)

	c.Collect(context.Background(), "dev-1")
	require.True(t, mustReport(t, c, "dev-1").Verified)

	verifier.err = errors.New("evidence could not be parsed")
	c.Collect(context.Background(), "dev-1")

	assert.True(t, mustReport(t, c, "dev-1").Verified,
		"an unevaluable verification must not overwrite a good report with a failure")
}

// TestCollector_NegativeVerdictIsStored is the counterpart: a verification
// that RAN and said no is a real result and must replace the cached one.
// Retaining a stale pass would be the opposite failure — hiding a device that
// has genuinely stopped attesting.
func TestCollector_NegativeVerdictIsStored(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1_700_000_000, 0).UTC())
	verifier := &stubVerifier{report: &Report{Verified: true, Status: "verified"}}
	c := testCollector(t, Config{Source: src, Verifier: verifier, Interval: time.Minute}, clk)

	c.Collect(context.Background(), "dev-1")
	require.True(t, mustReport(t, c, "dev-1").Verified)

	verifier.report = &Report{Verified: false, Status: "failed", SignatureValid: false, Message: "bad signature"}
	c.Collect(context.Background(), "dev-1")

	r := mustReport(t, c, "dev-1")
	assert.False(t, r.Verified, "a verification that ran and failed IS a result and must be stored")
	assert.Equal(t, "failed", r.Status)
	assert.False(t, r.SignatureValid, "the caller must be able to see WHICH check failed")
}

func mustReport(t *testing.T, c *Collector, id string) *Report {
	t.Helper()
	r, ok := c.Cache().Report(id)
	require.True(t, ok)
	return r
}

// waitFor polls a condition with a bounded deadline. It exists because the
// collector runs in a goroutine; it is a synchronisation bound, not a sleep
// standing in for one — the condition is the signal.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func waitForClose(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

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

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// Every test below drives runWithShutdownWatchdog — the SAME function
// runOrchestratorWithShutdownWatchdog delegates to. The previous version of
// this file defined a lookalike and tested that instead, so the production
// wiring (to orch.Run, to shutdownGrace, and whether a dump was emitted)
// was never exercised and could have regressed silently.
func runWatchdog(ctx context.Context, grace time.Duration, run func(context.Context) error) error {
	_, err := runWithShutdownWatchdog(ctx, grace, &bytes.Buffer{},
		func(c context.Context) (*bootstrap.BootstrapResult, error) { return nil, run(c) })
	return err
}

// The watchdog's contract, stated as behaviour rather than as timing:
//
//	1. a run that returns is reported verbatim, however long it took;
//	2. a run that returns AFTER cancellation but within the grace period is
//	   still reported verbatim — cancellation is not itself a failure;
//	3. a run that never returns after cancellation is reported as stuck.
//
// (3) is #135. (2) is the case a naive "cancelled means fail" watchdog would
// get wrong, turning every clean Ctrl-C into a spurious stuck-shutdown report.

func TestWatchdogReportsCompletedRunVerbatim(t *testing.T) {
	sentinel := errors.New("orchestrator said no")
	got := runWatchdog(context.Background(), time.Second, func(context.Context) error { return sentinel })
	if !errors.Is(got, sentinel) {
		t.Fatalf("got %v, want the orchestrator's own error", got)
	}
}

func TestWatchdogDoesNotFireWhenRunUnwindsWithinGrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled, as after a SIGTERM

	// The unwind is driven by CANCELLATION, not by a sleep. A well-behaved Run
	// returns because its context ended, so waiting on ctx.Done() models the
	// real thing and is deterministic under any scheduler. A wall-clock sleep
	// here would race the grace period and flake exactly when CI is saturated
	// (AGENTS.md forbids time.Sleep for synchronization) — and a watchdog test
	// that flakes under load would be reporting the very condition it exists to
	// distinguish from a real hang.
	got := runWatchdog(ctx, 2*time.Second, func(c context.Context) error {
		<-c.Done()
		return nil
	})
	if got != nil {
		t.Fatalf("got %v, want nil: a run that unwinds in response to cancellation is not stuck", got)
	}
}

func TestWatchdogReportsStuckShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Never released while the watchdog is deciding: this run ignores
	// cancellation entirely, which is #135's behaviour. The grace here is an
	// upper bound that must EXPIRE, and load can only delay that, never
	// prevent it — so the outcome is load-independent in the safe direction.
	blocked := make(chan struct{})
	defer close(blocked) // release the goroutine when the test ends
	got := runWatchdog(ctx, 50*time.Millisecond, func(context.Context) error {
		<-blocked
		return nil
	})
	var stuck ErrBootstrapShutdownStuck
	if !errors.As(got, &stuck) {
		t.Fatalf("got %v, want ErrBootstrapShutdownStuck", got)
	}
	if stuck.Grace != 50*time.Millisecond {
		t.Errorf("grace = %v, want it reported so the operator knows what was waited on", stuck.Grace)
	}
}

// TestWatchdogPropagatesResult pins that the production path returns the
// orchestrator's RESULT, not just its error — the result is what prints the
// Bootstrap Result table, whose absence is the visible symptom in #135.
func TestWatchdogPropagatesResult(t *testing.T) {
	want := &bootstrap.BootstrapResult{}
	got, err := runWithShutdownWatchdog(context.Background(), time.Second, &bytes.Buffer{},
		func(context.Context) (*bootstrap.BootstrapResult, error) { return want, nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("result not propagated: got %p, want %p", got, want)
	}
}

// TestWatchdogEmitsGoroutineDump pins the DIAGNOSTIC, which is the entire point
// of #135: without it a hang costs a SIGKILL and yields nothing. Asserting the
// error alone would pass even if the dump were silently dropped.
func TestWatchdogEmitsGoroutineDump(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	blocked := make(chan struct{})
	defer close(blocked)

	var sink bytes.Buffer
	_, err := runWithShutdownWatchdog(ctx, 50*time.Millisecond, &sink,
		func(context.Context) (*bootstrap.BootstrapResult, error) { <-blocked; return nil, nil })

	var stuck ErrBootstrapShutdownStuck
	if !errors.As(err, &stuck) {
		t.Fatalf("got %v, want ErrBootstrapShutdownStuck", err)
	}
	out := sink.String()
	if !strings.Contains(out, "dumping goroutines") {
		t.Errorf("dump banner missing; operator gets no diagnostic:\n%s", out)
	}
	// A real stack dump names goroutines and this test's own frame.
	if !strings.Contains(out, "goroutine ") {
		t.Errorf("no goroutine stacks in dump:\n%s", out)
	}
	if !strings.Contains(out, "TestWatchdogEmitsGoroutineDump") {
		t.Errorf("dump does not include the live stack that is actually stuck:\n%s", out)
	}
}

// blockingWriter never returns from Write, modelling stderr whose reader has
// stopped consuming: a full pipe, or a terminal that went away.
type blockingWriter struct{ entered chan struct{} }

func (b *blockingWriter) Write(p []byte) (int, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	select {} // block forever
}

// TestWatchdogReturnsWhenDiagnosticWriteBlocks is the reason dumpGoroutines
// bounds its own write.
//
// Without that bound this test hangs: the watchdog fires, writes the banner to
// a writer that never drains, and never returns. In production SIGTERM has by
// then been consumed by signal.NotifyContext, so the command would need SIGKILL
// and print nothing — #135 reproduced by the code written to diagnose #135.
func TestWatchdogReturnsWhenDiagnosticWriteBlocks(t *testing.T) {
	// Keep the bound short so a regression fails fast rather than stalling
	// the package until the go test timeout.
	restore := diagnosticWriteTimeoutForTest(200 * time.Millisecond)
	defer restore()

	w := &blockingWriter{entered: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := runWithShutdownWatchdog(ctx, 10*time.Millisecond, w,
			func(context.Context) (*bootstrap.BootstrapResult, error) {
				<-make(chan struct{}) // never unwinds, so the watchdog fires
				return nil, nil
			})
		done <- err
	}()

	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog never attempted to write its diagnostic")
	}

	select {
	case err := <-done:
		var stuck ErrBootstrapShutdownStuck
		if !errors.As(err, &stuck) {
			t.Fatalf("err = %v, want ErrBootstrapShutdownStuck", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog blocked on its own diagnostic write and never returned")
	}
}

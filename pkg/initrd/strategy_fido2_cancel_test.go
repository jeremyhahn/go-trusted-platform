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

package initrd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// blockingFIDO2 is an authenticator that waits for its touch: UnlockWithKey
// signals entered, then holds the key until the test releases it.
type blockingFIDO2 struct {
	*fakeFIDO2
	entered chan struct{}
	release chan struct{}
	key     []byte
}

func (f *blockingFIDO2) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	key, err := f.fakeFIDO2.UnlockWithKey(config)
	f.key = key
	close(f.entered)
	<-f.release
	return key, err
}

// lateKeyWriter is a log sink that signals discarded once the strategy
// reports the key it dropped after a cancellation.
type lateKeyWriter struct {
	once      sync.Once
	discarded chan struct{}
}

func (w *lateKeyWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("late FIDO2 key")) {
		w.once.Do(func() { close(w.discarded) })
	}
	return len(p), nil
}

// cancelledFIDO2Unlock is a boot unlock stopped inside the authenticator call:
// the context is already cancelled and the touch has not come yet.
type cancelledFIDO2Unlock struct {
	device    *blockingFIDO2
	volume    *tokenLUKS
	opened    int
	discarded chan struct{}
	result    chan error
}

func startCancelledFIDO2Unlock(t *testing.T) *cancelledFIDO2Unlock {
	t.Helper()
	enroller := newFakeFIDO2()
	volume := newTokenLUKS()
	installer := NewFIDO2Strategy(newFIDO2TestPlatform(enroller, volume), logging.DefaultLogger())
	if err := installer.Install(context.Background(), fido2TestVolume(), []byte("password")); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	u := &cancelledFIDO2Unlock{
		device: &blockingFIDO2{
			fakeFIDO2: enroller,
			entered:   make(chan struct{}),
			release:   make(chan struct{}),
		},
		volume:    volume,
		opened:    len(volume.opened),
		discarded: make(chan struct{}),
		result:    make(chan error, 1),
	}
	platform := createTestPlatform()
	platform.FIDO2 = u.device
	platform.LUKS = volume
	logger := logging.NewLogger(slog.LevelDebug, &lateKeyWriter{discarded: u.discarded})
	booter := NewFIDO2Strategy(platform, logger)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { u.result <- booter.Unlock(ctx, fido2TestVolume()) }()
	<-u.device.entered
	cancel()
	return u
}

// requireNeverOpened checks the outcome of the cancelled unlock, then waits
// for the late key to be dropped and checks that its bytes are gone.
func (u *cancelledFIDO2Unlock) requireNeverOpened(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Unlock = %v, want context.Canceled", err)
	}
	if got := len(u.volume.opened) - u.opened; got != 0 {
		t.Fatalf("Open was called %d time(s) after the cancellation", got)
	}

	<-u.discarded
	if len(u.device.key) == 0 {
		t.Fatal("the authenticator returned no key")
	}
	if !bytes.Equal(u.device.key, make([]byte, len(u.device.key))) {
		t.Error("the late key was not zeroed")
	}
	if got := len(u.volume.opened) - u.opened; got != 0 {
		t.Errorf("Open was called %d time(s) with the late key", got)
	}
}

// A touch that arrives after the context is cancelled must not open the
// volume: the key it yields is zeroed and dropped.
func TestFIDO2StrategyUnlockCancelledDuringTouch(t *testing.T) {
	u := startCancelledFIDO2Unlock(t)
	close(u.device.release)
	u.requireNeverOpened(t, <-u.result)
}

// A cancelled unlock does not wait for the touch: Unlock returns while the
// authenticator still blocks, and the key of the later touch is zeroed.
func TestFIDO2StrategyUnlockCancelledBeforeTouch(t *testing.T) {
	u := startCancelledFIDO2Unlock(t)
	err := <-u.result
	close(u.device.release)
	u.requireNeverOpened(t, err)
}

// gatedFIDO2 is an authenticator that survives several calls: every
// UnlockWithKey announces itself on entered and holds its key until the test
// releases that call. The embedded fake keeps no lock, so mu guards it.
type gatedFIDO2 struct {
	*fakeFIDO2
	mu      sync.Mutex
	calls   int
	entered chan *gatedFIDO2Call
	stop    chan struct{}
}

// gatedFIDO2Call is one UnlockWithKey call that waits for its touch.
type gatedFIDO2Call struct {
	key     []byte
	once    sync.Once
	release chan struct{}
}

// finish lets the call return its key, as a touch would.
func (c *gatedFIDO2Call) finish() { c.once.Do(func() { close(c.release) }) }

// newGatedFIDO2 wraps device; every call still blocked when the test ends is
// released then, so no later test waits on it.
func newGatedFIDO2(t *testing.T, device *fakeFIDO2) *gatedFIDO2 {
	t.Helper()
	g := &gatedFIDO2{
		fakeFIDO2: device,
		entered:   make(chan *gatedFIDO2Call, 8),
		stop:      make(chan struct{}),
	}
	t.Cleanup(func() { close(g.stop) })
	return g
}

func (g *gatedFIDO2) UnlockWithKey(config *fido2.AuthenticationConfig) ([]byte, error) {
	g.mu.Lock()
	g.calls++
	key, err := g.fakeFIDO2.UnlockWithKey(config)
	g.mu.Unlock()

	call := &gatedFIDO2Call{key: key, release: make(chan struct{})}
	g.entered <- call
	select {
	case <-call.release:
	case <-g.stop:
	}
	return key, err
}

// asked reports how many times the authenticator was asked for a key.
func (g *gatedFIDO2) asked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// logSignal is a log sink that closes seen at the first line with phrase.
type logSignal struct {
	phrase string
	once   sync.Once
	seen   chan struct{}
}

func newLogSignal(phrase string) *logSignal {
	return &logSignal{phrase: phrase, seen: make(chan struct{})}
}

func (w *logSignal) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(w.phrase)) {
		w.once.Do(func() { close(w.seen) })
	}
	return len(p), nil
}

// fido2GateWaitPhrase is in the line a strategy logs when it has to wait for
// another authenticator operation of the process.
const fido2GateWaitPhrase = "previous security key operation"

// abandonedFIDO2Unlock is an enrolled volume whose first boot unlock (A) was
// cancelled during the touch: Unlock returned context.Canceled and A's
// authenticator call still runs.
type abandonedFIDO2Unlock struct {
	device    *gatedFIDO2
	volume    *tokenLUKS
	enrolled  []byte
	opened    int
	abandoned *gatedFIDO2Call
	discarded chan struct{}
}

func startAbandonedFIDO2Unlock(t *testing.T) *abandonedFIDO2Unlock {
	t.Helper()
	enroller := newFakeFIDO2()
	volume := newTokenLUKS()
	installer := NewFIDO2Strategy(newFIDO2TestPlatform(enroller, volume), logging.DefaultLogger())
	if err := installer.Install(context.Background(), fido2TestVolume(), []byte("password")); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	a := &abandonedFIDO2Unlock{
		device:   newGatedFIDO2(t, enroller),
		volume:   volume,
		enrolled: bytes.Clone(volume.keys[fido2TestSlot]),
		opened:   len(volume.opened),
	}
	late := newLogSignal("late FIDO2 key")
	a.discarded = late.seen

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := a.unlock(ctx, late)
	select {
	case a.abandoned = <-a.device.entered:
	case err := <-result:
		t.Fatalf("unlock A returned %v before it asked the authenticator", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("unlock A = %v, want context.Canceled", err)
	}
	return a
}

// unlock starts a boot unlock on a fresh strategy over the same authenticator
// and volume; the strategy logs to sink.
func (a *abandonedFIDO2Unlock) unlock(ctx context.Context, sink *logSignal) chan error {
	platform := createTestPlatform()
	platform.FIDO2 = a.device
	platform.LUKS = a.volume
	strategy := NewFIDO2Strategy(platform, logging.NewLogger(slog.LevelDebug, sink))
	result := make(chan error, 1)
	go func() { result <- strategy.Unlock(ctx, fido2TestVolume()) }()
	return result
}

// requireWaiting checks that the retry whose strategy logs to waiting is held
// back while the abandoned call runs: it reports that it waits, and it has
// neither asked the authenticator nor returned.
func (a *abandonedFIDO2Unlock) requireWaiting(t *testing.T, waiting *logSignal, result chan error) {
	t.Helper()
	select {
	case <-waiting.seen:
	case <-a.device.entered:
		t.Fatal("the retry asked the authenticator while the abandoned call still runs")
	case err := <-result:
		t.Fatalf("the retry returned %v while the abandoned call still runs", err)
	}
	if got := a.device.asked(); got != 1 {
		t.Fatalf("the authenticator was asked %d time(s) while the abandoned call still runs, want 1", got)
	}
}

// endAbandoned lets the abandoned call return, waits until its late key was
// dropped, and checks that the key is zeroed and never reached Open.
func (a *abandonedFIDO2Unlock) endAbandoned(t *testing.T) {
	t.Helper()
	a.abandoned.finish()
	<-a.discarded
	if len(a.abandoned.key) == 0 {
		t.Fatal("the abandoned call returned no key")
	}
	if !bytes.Equal(a.abandoned.key, make([]byte, len(a.abandoned.key))) {
		t.Error("the late key of the abandoned call was not zeroed")
	}
	if got := len(a.volume.opened) - a.opened; got != 0 {
		t.Fatalf("Open was called %d time(s) with the late key", got)
	}
}

// requireUnlocks lets the unlock behind result enter the authenticator, gives
// it its touch, and checks that Open ran exactly once, with the enrolled key.
func (a *abandonedFIDO2Unlock) requireUnlocks(t *testing.T, result chan error) {
	t.Helper()
	select {
	case call := <-a.device.entered:
		call.finish()
	case err := <-result:
		t.Fatalf("the retry returned %v before it asked the authenticator", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	opened := a.volume.opened[a.opened:]
	if len(opened) != 1 {
		t.Fatalf("Open was called %d time(s), want 1", len(opened))
	}
	if !bytes.Equal(opened[0], a.enrolled) {
		t.Error("Open did not receive the enrolled key")
	}
}

// A retry after a cancelled unlock must not overlap the abandoned
// authenticator call on the shared handler: it waits until that call has
// ended and its late key is zeroed, and only then asks for its own touch.
func TestFIDO2StrategyRetryWaitsForAbandonedUnlock(t *testing.T) {
	a := startAbandonedFIDO2Unlock(t)

	waiting := newLogSignal(fido2GateWaitPhrase)
	result := a.unlock(context.Background(), waiting)
	a.requireWaiting(t, waiting, result)

	a.endAbandoned(t)
	a.requireUnlocks(t, result)
	if got := a.device.asked(); got != 2 {
		t.Errorf("the authenticator was asked %d time(s), want 2", got)
	}
}

// A retry cancelled while it waits returns the cancellation, never asks the
// authenticator, and leaves the gate to the abandoned call alone: once that
// call has ended, a third unlock succeeds.
func TestFIDO2StrategyRetryCancelledWhileWaiting(t *testing.T) {
	a := startAbandonedFIDO2Unlock(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	waiting := newLogSignal(fido2GateWaitPhrase)
	result := a.unlock(ctx, waiting)
	a.requireWaiting(t, waiting, result)

	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("the waiting retry = %v, want context.Canceled", err)
	}
	if got := a.device.asked(); got != 1 {
		t.Fatalf("the authenticator was asked %d time(s) after the waiting retry was cancelled, want 1", got)
	}
	if got := len(a.volume.opened) - a.opened; got != 0 {
		t.Fatalf("Open was called %d time(s) by the cancelled retry", got)
	}

	a.endAbandoned(t)
	third := a.unlock(context.Background(), newLogSignal(fido2GateWaitPhrase))
	a.requireUnlocks(t, third)
	if got := a.device.asked(); got != 2 {
		t.Errorf("the authenticator was asked %d time(s), want 2", got)
	}
}

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

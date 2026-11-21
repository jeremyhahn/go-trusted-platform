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

package backends

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
)

// blockingPlainFIDO2Handler is a minimal LUKSFIDO2Handler whose
// EnrollCredential signals entered and blocks until release is closed.
type blockingPlainFIDO2Handler struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (h *blockingPlainFIDO2Handler) EnrollCredential(context.Context, string, bool, bool) ([]byte, error) {
	h.calls.Add(1)
	h.entered <- struct{}{}
	<-h.release
	return []byte("fido2-hmac-secret-derived-key-32"), nil
}

// enrollFIDO2Async runs EnrollFIDO2 in a goroutine and returns its error
// channel.
func enrollFIDO2Async(ctx context.Context, b *LUKSBackend, device, credential string) <-chan error {
	errc := make(chan error, 1)
	go func() {
		_, err := b.EnrollFIDO2(ctx, &daemon.LUKSEnrollFIDO2Request{
			Device:             device,
			ExistingPassphrase: testLUKSPassphrase,
			CredentialID:       hex.EncodeToString([]byte(credential)),
		})
		errc <- err
	}()
	return errc
}

// assertQueuedFIDO2GivesUp starts a second and a third enrollment while the
// first holds the handler and checks each returns its ctx error within 2 s
// without entering the handler.
func assertQueuedFIDO2GivesUp(t *testing.T, b *LUKSBackend, entered <-chan struct{}) {
	t.Helper()
	timeoutCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	select {
	case err := <-enrollFIDO2Async(timeoutCtx, b, newLUKSImage(t), "cred-2"):
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued EnrollFIDO2 with a 100 ms timeout: err = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued EnrollFIDO2 ignored its 100 ms timeout for 2 s")
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	errc := enrollFIDO2Async(cancelCtx, b, newLUKSImage(t), "cred-3")
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued EnrollFIDO2 cancelled while waiting: err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued EnrollFIDO2 ignored its cancellation for 2 s")
	}

	select {
	case <-entered:
		t.Fatal("a queued enrollment entered the handler while the first held it")
	default:
	}
}

func TestLUKSBackend_QueuedFIDO2EnrollmentHonoursItsContext(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		h := &blockingPlainFIDO2Handler{entered: make(chan struct{}, 3), release: make(chan struct{})}
		var once sync.Once
		release := func() { once.Do(func() { close(h.release) }) }
		t.Cleanup(release)
		b := newTestLUKSBackend(WithLUKSFIDO2Handler(h))

		first := enrollFIDO2Async(context.Background(), b, newLUKSImage(t), "cred-1")
		<-h.entered
		assertQueuedFIDO2GivesUp(t, b, h.entered)
		if got := h.calls.Load(); got != 1 {
			t.Fatalf("handler called %d times while the first held it, want 1", got)
		}

		release()
		if err := <-first; err != nil {
			t.Fatalf("first EnrollFIDO2: %v", err)
		}
	})

	t.Run("rich", func(t *testing.T) {
		xk := &blockingXKMSFIDO2Handler{
			stubXKMSFIDO2Handler: newStubXKMSFIDO2Handler(nil),
			entered:              make(chan struct{}, 3),
			release:              make(chan struct{}),
		}
		var once sync.Once
		release := func() { once.Do(func() { close(xk.release) }) }
		t.Cleanup(release)
		h, err := NewLUKSFIDO2Handler(nil, xk, "example.com")
		if err != nil {
			t.Fatalf("NewLUKSFIDO2Handler: %v", err)
		}
		b := newTestLUKSBackend(WithLUKSFIDO2Handler(h))

		first := enrollFIDO2Async(context.Background(), b, newLUKSImage(t), "cred-1")
		<-xk.entered
		assertQueuedFIDO2GivesUp(t, b, xk.entered)

		release()
		if err := <-first; err != nil {
			t.Fatalf("first EnrollFIDO2: %v", err)
		}
		if xk.overlap.Load() {
			t.Fatal("two SDK calls ran at once")
		}
	})
}

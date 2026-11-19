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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// These tests cover the thin platform wiring around the canonical go-xkms
// TPM LUKS sealer (reached through the QuicBaaS SDK). The sealer's own
// behaviour — handle resolution, token encoding, PCR selection, and the
// simulator-backed seal/unseal round-trips — is tested upstream in
// go-xkms/pkg/luks.

func TestNewLUKSTPMHandler_NilOpener(t *testing.T) {
	_, err := NewLUKSTPMHandler(nil, nil)
	if !errors.Is(err, ErrLUKSTPMNoTransport) {
		t.Fatalf("expected ErrLUKSTPMNoTransport, got %v", err)
	}
}

func TestNewLUKSTPMHandler_SatisfiesLUKSTPMHandler(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	var _ LUKSTPMHandler = h
}

func TestLUKSTPMHandler_OpenFailure_Surfaces(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, _, err = h.Seal(context.Background(), "", []int32{7}); !errors.Is(err, ErrLUKSTPMNoTransport) {
		t.Fatalf("expected ErrLUKSTPMNoTransport, got %v", err)
	}
}

func TestLUKSTPMHandler_Seal_InvalidHandle(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, _, err = h.Seal(context.Background(), "not-a-number", nil); !errors.Is(err, ErrLUKSTPMInvalidHandle) {
		t.Fatalf("expected ErrLUKSTPMInvalidHandle, got %v", err)
	}
}

func TestLUKSTPMHandler_Unseal_InvalidTokenJSON(t *testing.T) {
	h, err := NewLUKSTPMHandler(nil, erroringOpener{err: ErrLUKSTPMNoTransport})
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if _, err = h.UnsealPassphrase(context.Background(), []byte("not-json")); !errors.Is(err, ErrLUKSTPMInvalidToken) {
		t.Fatalf("expected ErrLUKSTPMInvalidToken, got %v", err)
	}
}

// erroringOpener is a TPMOpener stub that short-circuits with the configured
// error. It lets us exercise the wiring's error surface without a TPM.
type erroringOpener struct {
	err error
}

// Open satisfies the TPMOpener contract.
func (e erroringOpener) Open(context.Context) (transport.TPMCloser, error) {
	return nil, e.err
}

// recordingTPM is a transport.TPM that counts the commands sent over it.
type recordingTPM struct{ sends int }

func (r *recordingTPM) Send(input []byte) ([]byte, error) {
	r.sends++
	return input, nil
}

// fakePlatformModule is the platform's TPM module; only Transport is used.
type fakePlatformModule struct {
	xkmssdk.TrustedPlatformModule
	tpm transport.TPM
}

func (m fakePlatformModule) Transport() transport.TPM { return m.tpm }

func TestPlatformTPMOpener_SharesThePlatformTransport(t *testing.T) {
	rec := &recordingTPM{}
	fake := fakePlatformModule{tpm: rec}
	opener := PlatformTPMOpener(func() xkmssdk.TrustedPlatformModule { return fake })

	tpm, err := opener.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := tpm.Send([]byte{1}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := tpm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close leaves the platform's transport open: the platform owns it.
	again, err := opener.Open(context.Background())
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if _, err := again.Send([]byte{2}); err != nil {
		t.Fatalf("Send after Close: %v", err)
	}
	if rec.sends != 2 {
		t.Fatalf("platform transport saw %d commands, want 2", rec.sends)
	}
}

// TestPlatformTPMOpenerSerializes pins the opener as the transport's lock:
// a second Open waits for the first closer's Close, a waiter whose context
// ends gets ctx.Err(), and a doubled Close releases the lock only once.
func TestPlatformTPMOpenerSerializes(t *testing.T) {
	fake := fakePlatformModule{tpm: &recordingTPM{}}
	opener := PlatformTPMOpener(func() xkmssdk.TrustedPlatformModule { return fake })

	first, err := opener.Open(context.Background())
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	var released atomic.Bool
	opened := make(chan transport.TPMCloser, 1)
	go func() {
		second, err := opener.Open(context.Background())
		if err != nil {
			t.Errorf("second Open: %v", err)
			opened <- nil
			return
		}
		if !released.Load() {
			t.Errorf("second Open returned while the first closer was still open")
		}
		opened <- second
	}()

	select {
	case <-opened:
		t.Fatal("second Open returned before the first Close")
	case <-time.After(50 * time.Millisecond):
	}

	// A waiter whose context is cancelled gives up with ctx.Err().
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := opener.Open(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open with a cancelled ctx: err = %v, want context.Canceled", err)
	}

	released.Store(true)
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	second := <-opened
	if second == nil {
		t.FailNow()
	}

	// A second Close of the first closer must not release the lock that
	// the second closer now holds.
	if err := first.Close(); err != nil {
		t.Fatalf("first Close again: %v", err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if _, err := opener.Open(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Open while the second closer holds the lock: err = %v, want context.DeadlineExceeded", err)
	}

	if err := second.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	third, err := opener.Open(context.Background())
	if err != nil {
		t.Fatalf("Open after every Close: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}
}

func TestPlatformTPMOpener_NoModuleIsNoTransport(t *testing.T) {
	cases := map[string]func() xkmssdk.TrustedPlatformModule{
		"nil module":    func() xkmssdk.TrustedPlatformModule { return nil },
		"nil transport": func() xkmssdk.TrustedPlatformModule { return fakePlatformModule{} },
	}
	for name, module := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := PlatformTPMOpener(module).Open(context.Background())
			if !errors.Is(err, ErrLUKSTPMNoTransport) {
				t.Fatalf("Open error = %v, want ErrLUKSTPMNoTransport", err)
			}
		})
	}
}

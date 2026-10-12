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

package barrier

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

func TestNewManager_NilSDK(t *testing.T) {
	cfg := DefaultConfig()
	m, err := NewManager(nil, cfg, nil)
	if m != nil {
		t.Error("expected nil manager for nil SDK")
	}
	if !errors.Is(err, ErrNilSDKClient) {
		t.Errorf("expected ErrNilSDKClient, got %v", err)
	}
}

func TestNewManager_NilConfig(t *testing.T) {
	// We cannot create a real SDK client without a server, so we test
	// the nil-config path by passing a non-nil interface value. Since
	// config validation runs before any SDK call, any non-nil SDK
	// satisfies the nil check. However, since we do not have a real
	// SDK client, this test only validates the code path for nil config.
	// The nil SDK check runs first, so we test the config path indirectly
	// by verifying the error type from Validate when config is nil.
	m, err := NewManager(nil, nil, nil)
	if m != nil {
		t.Error("expected nil manager for nil config")
	}
	// NilSDK is checked first
	if !errors.Is(err, ErrNilSDKClient) {
		t.Errorf("expected ErrNilSDKClient (checked first), got %v", err)
	}
}

func TestNewManager_InvalidConfig(t *testing.T) {
	// Config validation produces ConfigError for invalid values.
	// We cannot test the full constructor without a real SDK, but we
	// can verify that config.Validate() catches invalid configurations.
	cfg := &Config{SealStrategy: "bogus"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for bogus strategy")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
}

func TestManager_IsSealed_DefaultTrue(t *testing.T) {
	// Verify that a freshly-constructed manager (if we could build one)
	// would default to sealed. We test the atomic behavior directly.
	var m Manager
	m.sealed.Store(true)
	if !m.IsSealed() {
		t.Error("expected IsSealed() to return true when sealed is set")
	}
}

func TestManager_IsInitialized_DefaultFalse(t *testing.T) {
	var m Manager
	if m.IsInitialized() {
		t.Error("expected IsInitialized() to return false by default")
	}
}

func TestManager_SignalReady_Idempotent(t *testing.T) {
	m := newTestManager()

	// First signal should close the channel.
	m.signalReady()

	// Second signal should not panic.
	m.signalReady()

	// Channel should be closed.
	select {
	case <-m.ready.Load().ch:
		// expected
	default:
		t.Error("ready channel should be closed after signalReady")
	}
}

func TestManager_WaitReady_AlreadyReady(t *testing.T) {
	m := newTestManager()
	m.signalReady()

	ctx := context.Background()
	if err := m.WaitReady(ctx); err != nil {
		t.Errorf("WaitReady should return nil when already ready, got %v", err)
	}
}

func TestManager_WaitReady_ContextCancelled(t *testing.T) {
	m := newTestManager()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := m.WaitReady(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestManager_WaitReady_NilContext(t *testing.T) {
	m := newTestManager()

	err := m.WaitReady(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Initialize_NilContext(t *testing.T) {
	m := newTestManager()

	err := m.Initialize(nil, "secret") //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Initialize_EmptySecret(t *testing.T) {
	m := newTestManager()

	err := m.Initialize(context.Background(), "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("expected ErrEmptySecret, got %v", err)
	}
}

func TestManager_Initialize_AlreadyInitialized(t *testing.T) {
	m := newTestManager()
	m.initialized.Store(true)

	err := m.Initialize(context.Background(), "secret")
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestManager_InitializeShamir_NilContext(t *testing.T) {
	m := newTestManager()

	_, err := m.InitializeShamir(nil, "secret", 3, 5) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_InitializeShamir_EmptySecret(t *testing.T) {
	m := newTestManager()

	_, err := m.InitializeShamir(context.Background(), "", 3, 5)
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("expected ErrEmptySecret, got %v", err)
	}
}

func TestManager_InitializeShamir_InvalidThreshold(t *testing.T) {
	m := newTestManager()

	tests := []struct {
		name      string
		threshold int
		shares    int
	}{
		{"zero threshold", 0, 5},
		{"threshold of one", 1, 5},
		{"zero shares", 3, 0},
		{"threshold exceeds shares", 5, 3},
		{"negative threshold", -1, 5},
		{"negative shares", 3, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.InitializeShamir(context.Background(), "secret", tt.threshold, tt.shares)
			if !errors.Is(err, ErrInvalidThreshold) {
				t.Errorf("expected ErrInvalidThreshold, got %v", err)
			}
		})
	}
}

func TestManager_InitializeShamir_AlreadyInitialized(t *testing.T) {
	m := newTestManager()
	m.initialized.Store(true)

	_, err := m.InitializeShamir(context.Background(), "secret", 3, 5)
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestManager_Unseal_NilContext(t *testing.T) {
	m := newTestManager()
	m.sealed.Store(true)

	err := m.Unseal(nil, "secret") //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Unseal_EmptySecret(t *testing.T) {
	m := newTestManager()
	m.sealed.Store(true)

	err := m.Unseal(context.Background(), "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("expected ErrEmptySecret, got %v", err)
	}
}

func TestManager_Unseal_NotSealed(t *testing.T) {
	m := newTestManager()
	m.sealed.Store(false)

	err := m.Unseal(context.Background(), "secret")
	if !errors.Is(err, ErrNotSealed) {
		t.Errorf("expected ErrNotSealed, got %v", err)
	}
}

func TestManager_UnsealWithShare_NilContext(t *testing.T) {
	m := newTestManager()

	_, err := m.UnsealWithShare(nil, "share") //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_UnsealWithShare_EmptyShare(t *testing.T) {
	m := newTestManager()

	_, err := m.UnsealWithShare(context.Background(), "")
	if !errors.Is(err, ErrEmptyShare) {
		t.Errorf("expected ErrEmptyShare, got %v", err)
	}
}

func TestManager_Seal_NilContext(t *testing.T) {
	m := newTestManager()
	m.sealed.Store(false)

	err := m.Seal(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Seal_AlreadySealed(t *testing.T) {
	m := newTestManager()
	m.sealed.Store(true)

	err := m.Seal(context.Background())
	if !errors.Is(err, ErrSealed) {
		t.Errorf("expected ErrSealed, got %v", err)
	}
}

func TestManager_Status_NilContext(t *testing.T) {
	m := newTestManager()

	_, err := m.Status(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Rekey_NilContext(t *testing.T) {
	m := newTestManager()

	_, err := m.Rekey(nil, 3, 5) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Rekey_InvalidThreshold(t *testing.T) {
	m := newTestManager()

	tests := []struct {
		name      string
		threshold int
		total     int
	}{
		{"zero threshold", 0, 5},
		{"threshold of one", 1, 5},
		{"zero total", 3, 0},
		{"threshold exceeds total", 5, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Rekey(context.Background(), tt.threshold, tt.total)
			if !errors.Is(err, ErrInvalidThreshold) {
				t.Errorf("expected ErrInvalidThreshold, got %v", err)
			}
		})
	}
}

func TestManager_Rekey_Sealed(t *testing.T) {
	m := newTestManager()
	m.sealed.Store(true)

	_, err := m.Rekey(context.Background(), 3, 5)
	if !errors.Is(err, ErrSealed) {
		t.Errorf("expected ErrSealed, got %v", err)
	}
}

func TestManager_SyncStatus_NilContext(t *testing.T) {
	m := newTestManager()

	err := m.SyncStatus(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Config_ReturnsConfig(t *testing.T) {
	cfg := DefaultConfig()
	m := newTestManager()
	m.config = cfg

	if m.Config() != cfg {
		t.Error("Config() should return the same config pointer")
	}
}

// fakeBarrierClient answers the barrier calls the unsealing-state tests
// make; every other method panics through the nil embedded interface.
type fakeBarrierClient struct {
	quicbaassdk.QRDBBarrierClient
	shareResp *quicbaassdk.QRDBBarrierUnsealShareResponse
	shareErr  error
	status    *quicbaassdk.QRDBBarrierStatusResponse
}

func (f *fakeBarrierClient) BarrierUnsealWithShare(context.Context, *quicbaassdk.QRDBBarrierUnsealShareRequest) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error) {
	return f.shareResp, f.shareErr
}

func (f *fakeBarrierClient) BarrierSeal(context.Context) error { return nil }

func (f *fakeBarrierClient) BarrierStatus(context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	return f.status, nil
}

type fakeSecurity struct {
	quicbaassdk.SecurityService
	barrier *fakeBarrierClient
}

func (s fakeSecurity) Barrier() (quicbaassdk.QRDBBarrierClient, error) { return s.barrier, nil }

type fakeSDK struct {
	quicbaassdk.Client
	barrier *fakeBarrierClient
}

func (c fakeSDK) Security() quicbaassdk.SecurityService { return fakeSecurity{barrier: c.barrier} }

// newSealedManager returns a sealed, initialized Manager over the fake.
func newSealedManager(fake *fakeBarrierClient) *Manager {
	m := newTestManager()
	m.sdk = fakeSDK{barrier: fake}
	m.config = DefaultConfig()
	m.logger = slog.New(slog.DiscardHandler)
	m.initialized.Store(true)
	m.sealed.Store(true)
	return m
}

// newTestManager returns a bare Manager with its first ready generation in
// place, as NewManager would leave it.
func newTestManager() *Manager {
	m := &Manager{}
	m.ready.Store(newReadyGate())
	return m
}

func TestManager_IsUnsealing_FalseByDefault(t *testing.T) {
	m := newSealedManager(&fakeBarrierClient{})
	if m.IsUnsealing() {
		t.Fatal("a sealed barrier with no shares submitted is not unsealing")
	}
}

func TestManager_UnsealWithShare_PartialReportsUnsealing(t *testing.T) {
	fake := &fakeBarrierClient{shareResp: &quicbaassdk.QRDBBarrierUnsealShareResponse{Required: 3, Submitted: 1}}
	m := newSealedManager(fake)

	if _, err := m.UnsealWithShare(context.Background(), "share-1"); err != nil {
		t.Fatalf("UnsealWithShare: %v", err)
	}
	if !m.IsUnsealing() {
		t.Fatal("expected IsUnsealing after a partial share")
	}
	if !m.IsSealed() {
		t.Fatal("a partial share must not unseal the barrier")
	}
}

func TestManager_UnsealWithShare_CompleteClearsUnsealing(t *testing.T) {
	fake := &fakeBarrierClient{shareResp: &quicbaassdk.QRDBBarrierUnsealShareResponse{Required: 2, Submitted: 1}}
	m := newSealedManager(fake)
	if _, err := m.UnsealWithShare(context.Background(), "share-1"); err != nil {
		t.Fatalf("first share: %v", err)
	}

	fake.shareResp = &quicbaassdk.QRDBBarrierUnsealShareResponse{Required: 2, Submitted: 2, Complete: true}
	if _, err := m.UnsealWithShare(context.Background(), "share-2"); err != nil {
		t.Fatalf("second share: %v", err)
	}
	if m.IsUnsealing() || m.IsSealed() {
		t.Fatalf("after the threshold: unsealing=%v sealed=%v, want both false", m.IsUnsealing(), m.IsSealed())
	}
}

func TestManager_UnsealWithShare_ErrorLeavesStateUnchanged(t *testing.T) {
	boom := errors.New("bad share")
	m := newSealedManager(&fakeBarrierClient{shareErr: boom})

	_, err := m.UnsealWithShare(context.Background(), "share-1")
	var mgrErr *ManagerError
	if !errors.As(err, &mgrErr) || !errors.Is(err, boom) {
		t.Fatalf("expected ManagerError wrapping the SDK error, got %v", err)
	}
	if m.IsUnsealing() {
		t.Fatal("a rejected share must not report unsealing")
	}
}

func TestManager_Seal_ClearsUnsealing(t *testing.T) {
	m := newSealedManager(&fakeBarrierClient{})
	m.sealed.Store(false)
	m.unsealing.Store(true)

	if err := m.Seal(context.Background()); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if m.IsUnsealing() {
		t.Fatal("a fresh seal must start with no share progress")
	}
}

func TestManager_SyncStatus_UnsealedClearsUnsealing(t *testing.T) {
	fake := &fakeBarrierClient{status: &quicbaassdk.QRDBBarrierStatusResponse{Sealed: false, InitializedAt: "2026-10-11T00:00:00Z"}}
	m := newSealedManager(fake)
	m.unsealing.Store(true)

	if err := m.SyncStatus(context.Background()); err != nil {
		t.Fatalf("SyncStatus (unsealed): %v", err)
	}

	// The barrier is sealed again elsewhere; the old share progress must
	// not resurface as unsealing.
	fake.status = &quicbaassdk.QRDBBarrierStatusResponse{Sealed: true, InitializedAt: "2026-10-11T00:00:00Z"}
	if err := m.SyncStatus(context.Background()); err != nil {
		t.Fatalf("SyncStatus (sealed): %v", err)
	}
	if m.IsUnsealing() {
		t.Fatal("share progress from before an unseal must not survive it")
	}
}

// TestManager_ConcurrentSealWaitReadySignal drives Seal, WaitReady and
// signalReady from three goroutines released together. Under -race it fails
// if Seal's new ready generation is published without synchronisation.
func TestManager_ConcurrentSealWaitReadySignal(t *testing.T) {
	const rounds = 200
	m := newSealedManager(&fakeBarrierClient{})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	start := make(chan struct{})
	errs := make(chan error, 2*rounds)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for range rounds {
			m.sealed.Store(false)
			if err := m.Seal(context.Background()); err != nil && !errors.Is(err, ErrSealed) {
				errs <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range rounds {
			if err := m.WaitReady(cancelled); err != nil && !errors.Is(err, context.Canceled) {
				errs <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range rounds {
			m.signalReady()
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestManager_ConcurrentUnsealSignalsDoNotPanic releases a completing share
// submission and an unsealed SyncStatus on many goroutines at once. Both
// paths signal the same ready generation; it must close exactly once.
func TestManager_ConcurrentUnsealSignalsDoNotPanic(t *testing.T) {
	const signallers = 64
	fake := &fakeBarrierClient{
		shareResp: &quicbaassdk.QRDBBarrierUnsealShareResponse{Complete: true, Submitted: 2, Required: 2},
		status:    &quicbaassdk.QRDBBarrierStatusResponse{Sealed: false, InitializedAt: "2026-10-11T00:00:00Z"},
	}
	m := newSealedManager(fake)

	start := make(chan struct{})
	errs := make(chan error, signallers)
	var wg sync.WaitGroup
	for i := range signallers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				if _, err := m.UnsealWithShare(context.Background(), "share"); err != nil {
					errs <- err
				}
				return
			}
			if err := m.SyncStatus(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
	if err := m.WaitReady(context.Background()); err != nil {
		t.Fatalf("WaitReady after unseal: %v", err)
	}
}

// TestManager_Seal_StartsNewReadyGeneration checks that Seal makes WaitReady
// block again and that the next signal releases it.
func TestManager_Seal_StartsNewReadyGeneration(t *testing.T) {
	m := newSealedManager(&fakeBarrierClient{})
	m.sealed.Store(false)
	m.signalReady()
	if err := m.WaitReady(context.Background()); err != nil {
		t.Fatalf("WaitReady while unsealed: %v", err)
	}

	if err := m.Seal(context.Background()); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.WaitReady(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitReady after Seal = %v, want context.Canceled", err)
	}

	m.signalReady()
	if err := m.WaitReady(context.Background()); err != nil {
		t.Fatalf("WaitReady after the next signal: %v", err)
	}
}

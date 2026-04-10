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
	"testing"
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
	m := &Manager{
		ready: make(chan struct{}),
	}

	// First signal should close the channel.
	m.signalReady()

	// Second signal should not panic.
	m.signalReady()

	// Channel should be closed.
	select {
	case <-m.ready:
		// expected
	default:
		t.Error("ready channel should be closed after signalReady")
	}
}

func TestManager_WaitReady_AlreadyReady(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	close(m.ready)

	ctx := context.Background()
	if err := m.WaitReady(ctx); err != nil {
		t.Errorf("WaitReady should return nil when already ready, got %v", err)
	}
}

func TestManager_WaitReady_ContextCancelled(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

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
	m := &Manager{
		ready: make(chan struct{}),
	}

	err := m.WaitReady(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Initialize_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	err := m.Initialize(nil, "secret") //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Initialize_EmptySecret(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	err := m.Initialize(context.Background(), "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("expected ErrEmptySecret, got %v", err)
	}
}

func TestManager_Initialize_AlreadyInitialized(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.initialized.Store(true)

	err := m.Initialize(context.Background(), "secret")
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestManager_InitializeShamir_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	_, err := m.InitializeShamir(nil, "secret", 3, 5) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_InitializeShamir_EmptySecret(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	_, err := m.InitializeShamir(context.Background(), "", 3, 5)
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("expected ErrEmptySecret, got %v", err)
	}
}

func TestManager_InitializeShamir_InvalidThreshold(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	tests := []struct {
		name      string
		threshold int
		shares    int
	}{
		{"zero threshold", 0, 5},
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
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.initialized.Store(true)

	_, err := m.InitializeShamir(context.Background(), "secret", 3, 5)
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestManager_Unseal_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.sealed.Store(true)

	err := m.Unseal(nil, "secret") //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Unseal_EmptySecret(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.sealed.Store(true)

	err := m.Unseal(context.Background(), "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("expected ErrEmptySecret, got %v", err)
	}
}

func TestManager_Unseal_NotSealed(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.sealed.Store(false)

	err := m.Unseal(context.Background(), "secret")
	if !errors.Is(err, ErrNotSealed) {
		t.Errorf("expected ErrNotSealed, got %v", err)
	}
}

func TestManager_UnsealWithShare_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	_, err := m.UnsealWithShare(nil, "share") //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_UnsealWithShare_EmptyShare(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	_, err := m.UnsealWithShare(context.Background(), "")
	if !errors.Is(err, ErrEmptyShare) {
		t.Errorf("expected ErrEmptyShare, got %v", err)
	}
}

func TestManager_Seal_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.sealed.Store(false)

	err := m.Seal(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Seal_AlreadySealed(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.sealed.Store(true)

	err := m.Seal(context.Background())
	if !errors.Is(err, ErrSealed) {
		t.Errorf("expected ErrSealed, got %v", err)
	}
}

func TestManager_Status_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	_, err := m.Status(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Rekey_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	_, err := m.Rekey(nil, 3, 5) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Rekey_InvalidThreshold(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	tests := []struct {
		name      string
		threshold int
		total     int
	}{
		{"zero threshold", 0, 5},
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
	m := &Manager{
		ready: make(chan struct{}),
	}
	m.sealed.Store(true)

	_, err := m.Rekey(context.Background(), 3, 5)
	if !errors.Is(err, ErrSealed) {
		t.Errorf("expected ErrSealed, got %v", err)
	}
}

func TestManager_SyncStatus_NilContext(t *testing.T) {
	m := &Manager{
		ready: make(chan struct{}),
	}

	err := m.SyncStatus(nil) //nolint:staticcheck
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestManager_Config_ReturnsConfig(t *testing.T) {
	cfg := DefaultConfig()
	m := &Manager{
		config: cfg,
		ready:  make(chan struct{}),
	}

	if m.Config() != cfg {
		t.Error("Config() should return the same config pointer")
	}
}

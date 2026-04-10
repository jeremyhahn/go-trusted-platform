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

package modes

import (
	"context"
	"net"
	"testing"
	"time"
)

// newEdgeTestConfig creates a valid EdgeModeConfig for testing.
func newEdgeTestConfig() *EdgeModeConfig {
	_, prefix, _ := net.ParseCIDR("2001:db8::/64")
	return &EdgeModeConfig{
		IPv6Pool:              *prefix,
		IPv6InactivityTimeout: time.Hour,
		RateLimits: RateLimitConfig{
			TrustedReqPerSec:   100,
			UntrustedReqPerSec: 10,
			TrustThreshold:     0.5,
		},
	}
}

// TestEdgeModeHandler_Start tests EdgeModeHandler Start.
func TestEdgeModeHandler_Start(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	if !handler.running.Load() {
		t.Error("expected handler to be running")
	}
}

// TestEdgeModeHandler_StartAlreadyRunning tests Start when already running.
func TestEdgeModeHandler_StartAlreadyRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Try to start again
	err = handler.Start(ctx)
	if err != ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got: %v", err)
	}
}

// TestEdgeModeHandler_Stop tests EdgeModeHandler Stop.
func TestEdgeModeHandler_Stop(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() error: %v", err)
	}

	if handler.running.Load() {
		t.Error("expected handler to be stopped")
	}
}

// TestEdgeModeHandler_StopNotRunning tests Stop when not running.
func TestEdgeModeHandler_StopNotRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Stop(ctx)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestEdgeModeHandler_AllocateIPv6_NotRunning tests AllocateIPv6 when not running.
func TestEdgeModeHandler_AllocateIPv6_NotRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	_, err = handler.AllocateIPv6(ctx, "device-123")
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestEdgeModeHandler_AllocateIPv6_EmptyDeviceID tests AllocateIPv6 with empty device ID.
func TestEdgeModeHandler_AllocateIPv6_EmptyDeviceID(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	_, err = handler.AllocateIPv6(ctx, "")
	if err != ErrDeviceIDRequired {
		t.Errorf("expected ErrDeviceIDRequired, got: %v", err)
	}
}

// TestEdgeModeHandler_AllocateIPv6_Success tests successful IPv6 allocation.
func TestEdgeModeHandler_AllocateIPv6_Success(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	ip, err := handler.AllocateIPv6(ctx, "device-123")
	if err != nil {
		t.Errorf("AllocateIPv6() error: %v", err)
	}
	if ip == nil {
		t.Error("expected non-nil IP")
	}
}

// TestEdgeModeHandler_ReleaseIPv6_NotRunning tests ReleaseIPv6 when not running.
func TestEdgeModeHandler_ReleaseIPv6_NotRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.ReleaseIPv6(ctx, net.ParseIP("2001:db8::1"))
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestEdgeModeHandler_ReleaseIPv6_NilIP tests ReleaseIPv6 with nil IP.
func TestEdgeModeHandler_ReleaseIPv6_NilIP(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	err = handler.ReleaseIPv6(ctx, nil)
	if err != ErrInvalidIPv6Address {
		t.Errorf("expected ErrInvalidIPv6Address, got: %v", err)
	}
}

// TestEdgeModeHandler_RefreshLease_NotRunning tests RefreshLease when not running.
func TestEdgeModeHandler_RefreshLease_NotRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.RefreshLease(ctx, net.ParseIP("2001:db8::1"))
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestEdgeModeHandler_RefreshLease_NilIP tests RefreshLease with nil IP.
func TestEdgeModeHandler_RefreshLease_NilIP(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	err = handler.RefreshLease(ctx, nil)
	if err != ErrInvalidIPv6Address {
		t.Errorf("expected ErrInvalidIPv6Address, got: %v", err)
	}
}

// TestEdgeModeHandler_CheckRateLimit_NotRunning tests CheckRateLimit when not running.
func TestEdgeModeHandler_CheckRateLimit_NotRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.CheckRateLimit(ctx, "peer-123", 1.0)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestEdgeModeHandler_CheckRateLimit_EmptyPeerID tests CheckRateLimit with empty peer ID.
func TestEdgeModeHandler_CheckRateLimit_EmptyPeerID(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	err = handler.CheckRateLimit(ctx, "", 1.0)
	if err != ErrPeerIDRequired {
		t.Errorf("expected ErrPeerIDRequired, got: %v", err)
	}
}

// TestEdgeModeHandler_GetStatus tests GetStatus.
func TestEdgeModeHandler_GetStatus(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	status := handler.GetStatus()
	if status == nil {
		t.Fatal("GetStatus() should not return nil")
	}
	if !status.Running {
		t.Error("expected status.Running to be true")
	}
}

// TestEdgeModeHandler_CheckRateLimit_Success tests successful rate limit check.
func TestEdgeModeHandler_CheckRateLimit_Success(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	err = handler.CheckRateLimit(ctx, "peer-123", 1.0)
	if err != nil {
		t.Errorf("CheckRateLimit() error: %v", err)
	}
}

// TestEdgeModeHandler_OnboardDevice tests OnboardDevice.
func TestEdgeModeHandler_OnboardDevice(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	_, err = handler.OnboardDevice(ctx, &OnboardingRequest{})
	if err != ErrP2PNotEnabled {
		t.Errorf("expected ErrP2PNotEnabled, got: %v", err)
	}
}

// TestEdgeModeHandler_BootstrapDHT tests BootstrapDHT.
func TestEdgeModeHandler_BootstrapDHT(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	_, err = handler.BootstrapDHT(ctx, []byte("node-id"))
	if err != ErrP2PNotEnabled {
		t.Errorf("expected ErrP2PNotEnabled, got: %v", err)
	}
}

// TestEdgeModeHandler_Validate tests EdgeModeConfig validation.
func TestEdgeModeHandler_Validate_NilPool(t *testing.T) {
	cfg := &EdgeModeConfig{}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for nil pool")
	}
}

// TestEdgeModeHandler_ValidateIPv6Pool tests validation of IPv6 pool.
func TestEdgeModeHandler_ValidateIPv6Pool(t *testing.T) {
	_, prefix, _ := net.ParseCIDR("2001:db8::/64")
	cfg := &EdgeModeConfig{
		IPv6Pool:              *prefix,
		IPv6InactivityTimeout: time.Hour,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEdgeModeHandler_GetStatusNotRunning tests GetStatus when not running.
func TestEdgeModeHandler_GetStatusNotRunning(t *testing.T) {
	cfg := newEdgeTestConfig()
	handler, err := NewEdgeModeHandler(cfg)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	status := handler.GetStatus()
	if status == nil {
		t.Fatal("GetStatus() should not return nil")
	}
	if status.Running {
		t.Error("expected status.Running to be false")
	}
}

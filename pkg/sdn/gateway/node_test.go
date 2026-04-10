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

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"
)

// validConfig returns a valid gateway configuration for testing.
func validConfig() *GatewayConfig {
	return &GatewayConfig{
		Enabled:       true,
		ID:            "test-gateway",
		NodeID:        12345,
		Modes:         []GatewayMode{GatewayModeOverlay},
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
	}
}

// validNodeMetrics returns valid metrics that meet all requirements.
func validNodeMetrics() (float64, time.Duration, float64) {
	reputation := 0.90
	age := time.Duration(MinAgeDays+10) * 24 * time.Hour
	uptime := 99.0
	return reputation, age, uptime
}

func TestNewGateway(t *testing.T) {
	tests := []struct {
		name        string
		config      *GatewayConfig
		expectError error
	}{
		{
			name:        "valid config",
			config:      validConfig(),
			expectError: nil,
		},
		{
			name:        "nil config",
			config:      nil,
			expectError: ErrConfigNil,
		},
		{
			name: "invalid config - no modes",
			config: func() *GatewayConfig {
				cfg := validConfig()
				cfg.Modes = nil
				return cfg
			}(),
			expectError: ErrConfigurationInvalid,
		},
		{
			name: "invalid config - empty ID",
			config: func() *GatewayConfig {
				cfg := validConfig()
				cfg.ID = ""
				return cfg
			}(),
			expectError: ErrConfigurationInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw, err := NewGateway(tt.config)
			if tt.expectError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectError)
				}
				if !errors.Is(err, tt.expectError) {
					// Check if it's a wrapper error
					var modeErr *ErrModeNotSupported
					if !errors.As(err, &modeErr) && err.Error() != tt.expectError.Error() {
						t.Errorf("expected error %v, got %v", tt.expectError, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gw == nil {
				t.Fatal("gateway is nil")
			}
			if gw.config != tt.config {
				t.Error("gateway config does not match")
			}
			if gw.node == nil {
				t.Error("gateway node is nil")
			}
			if gw.GetState() != GatewayStateStopped {
				t.Errorf("initial state = %v, want %v", gw.GetState(), GatewayStateStopped)
			}
		})
	}
}

func TestGateway_StartStop(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Set valid metrics
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()

	// Start the gateway
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}

	// Verify running state
	if !gw.IsRunning() {
		t.Error("gateway should be running after Start")
	}
	if gw.GetState() != GatewayStateRunning {
		t.Errorf("state = %v, want %v", gw.GetState(), GatewayStateRunning)
	}

	// Start again should fail
	if err := gw.Start(ctx); err == nil {
		t.Error("expected error when starting already running gateway")
	} else if !errors.Is(err, ErrGatewayAlreadyRunning) {
		t.Errorf("expected ErrGatewayAlreadyRunning, got %v", err)
	}

	// Stop the gateway
	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("failed to stop gateway: %v", err)
	}

	// Verify stopped state
	if gw.IsRunning() {
		t.Error("gateway should not be running after Stop")
	}
	if gw.GetState() != GatewayStateStopped {
		t.Errorf("state = %v, want %v", gw.GetState(), GatewayStateStopped)
	}

	// Stop again should be idempotent
	if err := gw.Stop(ctx); err != nil {
		t.Errorf("stopping already stopped gateway should not error: %v", err)
	}
}

func TestGateway_StartWithInvalidMetrics(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	ctx := context.Background()

	// Don't set metrics (default zero values)
	err = gw.Start(ctx)
	if err == nil {
		t.Fatal("expected error when starting with invalid metrics")
	}

	var startErr *ErrStartupFailed
	if !errors.As(err, &startErr) {
		t.Errorf("expected ErrStartupFailed, got %T: %v", err, err)
	}

	// Verify gateway is not running
	if gw.IsRunning() {
		t.Error("gateway should not be running after failed start")
	}
}

func TestGateway_ActivateDeactivateMode(t *testing.T) {
	// Start with only overlay mode configured
	cfg := validConfig()
	cfg.Modes = []GatewayMode{GatewayModeOverlay}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()

	// Can't activate mode when not running
	if err := gw.ActivateMode(ctx, GatewayModeEdge); err == nil {
		t.Error("expected error when activating mode on stopped gateway")
	}

	// Start gateway (overlay mode will be auto-activated)
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}

	// Verify overlay mode is active
	if !gw.HasMode(GatewayModeOverlay) {
		t.Error("overlay mode should be active after start")
	}

	// Activate same mode again should fail
	if err := gw.ActivateMode(ctx, GatewayModeOverlay); err == nil {
		t.Error("expected error when activating already active mode")
	}

	// Activate edge mode
	if err := gw.ActivateMode(ctx, GatewayModeEdge); err != nil {
		t.Fatalf("failed to activate edge mode: %v", err)
	}

	// Verify both modes are active
	if !gw.HasMode(GatewayModeOverlay) || !gw.HasMode(GatewayModeEdge) {
		t.Error("both overlay and edge modes should be active")
	}

	// Deactivate overlay mode
	if err := gw.DeactivateMode(ctx, GatewayModeOverlay); err != nil {
		t.Fatalf("failed to deactivate overlay mode: %v", err)
	}

	// Verify overlay is inactive
	if gw.HasMode(GatewayModeOverlay) {
		t.Error("overlay mode should be inactive")
	}

	// Deactivate same mode again should fail
	if err := gw.DeactivateMode(ctx, GatewayModeOverlay); err == nil {
		t.Error("expected error when deactivating inactive mode")
	}

	// Stop gateway
	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("failed to stop gateway: %v", err)
	}
}

func TestGateway_ActivateModeInvalidMode(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Try to activate invalid mode
	if err := gw.ActivateMode(ctx, GatewayMode(0)); err == nil {
		t.Error("expected error when activating invalid mode")
	}
}

func TestGateway_DeactivateModeInvalidMode(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Try to deactivate invalid mode
	if err := gw.DeactivateMode(ctx, GatewayMode(0)); err == nil {
		t.Error("expected error when deactivating invalid mode")
	}
}

func TestGateway_GetStatus(t *testing.T) {
	cfg := validConfig()
	cfg.Modes = []GatewayMode{GatewayModeOverlay, GatewayModeEdge}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Status when stopped
	status := gw.GetStatus()
	if status.State != GatewayStateStopped {
		t.Errorf("status state = %v, want %v", status.State, GatewayStateStopped)
	}
	if status.ID != cfg.ID {
		t.Errorf("status ID = %q, want %q", status.ID, cfg.ID)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Status when running
	status = gw.GetStatus()
	if status.State != GatewayStateRunning {
		t.Errorf("status state = %v, want %v", status.State, GatewayStateRunning)
	}
	if status.StartedAt.IsZero() {
		t.Error("status StartedAt should not be zero")
	}
	if !status.ActiveModes.HasMode(GatewayModeOverlay) {
		t.Error("status should show overlay mode active")
	}
	if !status.ActiveModes.HasMode(GatewayModeEdge) {
		t.Error("status should show edge mode active")
	}
	if status.OverlayState == nil {
		t.Error("status should have overlay state")
	}
	if status.EdgeState == nil {
		t.Error("status should have edge state")
	}
}

func TestGateway_MeetsRequirements(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Without setting metrics, should fail
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when requirements not met")
	}

	// Set valid metrics
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	// Should pass now
	if err := gw.MeetsRequirements(); err != nil {
		t.Errorf("expected requirements to be met: %v", err)
	}

	// Set low reputation
	gw.SetNodeMetrics(0.5, age, uptime)
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when reputation too low")
	}

	// Reset and set low age
	gw.SetNodeMetrics(rep, 10*24*time.Hour, uptime)
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when age too young")
	}

	// Reset and set low uptime
	gw.SetNodeMetrics(rep, age, 50.0)
	if err := gw.MeetsRequirements(); err == nil {
		t.Error("expected error when uptime too low")
	}
}

func TestGateway_IsOperational(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Not operational when stopped
	if gw.IsOperational() {
		t.Error("gateway should not be operational when stopped")
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Operational when running
	if !gw.IsOperational() {
		t.Error("gateway should be operational when running")
	}
}

func TestGateway_GetNode(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	node := gw.GetNode()
	if node.ID != cfg.ID {
		t.Errorf("node ID = %q, want %q", node.ID, cfg.ID)
	}
	if node.NodeID != cfg.NodeID {
		t.Errorf("node NodeID = %d, want %d", node.NodeID, cfg.NodeID)
	}
}

func TestGateway_GetConfig(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	gotCfg := gw.GetConfig()
	if gotCfg != cfg {
		t.Error("GetConfig should return the same config instance")
	}
}

func TestGateway_GetActiveModes(t *testing.T) {
	cfg := validConfig()
	cfg.Modes = []GatewayMode{GatewayModeOverlay, GatewayModeTransit}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	modes := gw.GetActiveModes()
	if !modes.HasMode(GatewayModeOverlay) {
		t.Error("should have overlay mode")
	}
	if !modes.HasMode(GatewayModeTransit) {
		t.Error("should have transit mode")
	}
	if modes.HasMode(GatewayModeEdge) {
		t.Error("should not have edge mode")
	}
}

func TestGateway_SetNodeMetrics(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep := 0.95
	age := 200 * 24 * time.Hour
	uptime := 99.5

	gw.SetNodeMetrics(rep, age, uptime)

	node := gw.GetNode()
	if node.Reputation != rep {
		t.Errorf("reputation = %v, want %v", node.Reputation, rep)
	}
	if node.Age != age {
		t.Errorf("age = %v, want %v", node.Age, age)
	}
	if node.Uptime != uptime {
		t.Errorf("uptime = %v, want %v", node.Uptime, uptime)
	}
}

func TestGateway_Uptime(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Uptime when stopped should be 0
	if gw.Uptime() != 0 {
		t.Errorf("uptime when stopped = %v, want 0", gw.Uptime())
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Uptime when running should be > 0
	if gw.Uptime() == 0 {
		t.Error("uptime when running should be > 0")
	}
}

func TestGateway_AllModes(t *testing.T) {
	cfg := validConfig()
	cfg.Modes = []GatewayMode{GatewayModeOverlay, GatewayModeEdge, GatewayModeTransit}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Verify all modes are active
	if !gw.HasMode(GatewayModeOverlay) {
		t.Error("should have overlay mode")
	}
	if !gw.HasMode(GatewayModeEdge) {
		t.Error("should have edge mode")
	}
	if !gw.HasMode(GatewayModeTransit) {
		t.Error("should have transit mode")
	}

	// Verify all state objects exist
	status := gw.GetStatus()
	if status.OverlayState == nil {
		t.Error("should have overlay state")
	}
	if status.EdgeState == nil {
		t.Error("should have edge state")
	}
	if status.TransitState == nil {
		t.Error("should have transit state")
	}
}

func TestModeHandler_OverlayMode(t *testing.T) {
	// Use a config with a valid mode so it passes validation
	cfg := validConfig()

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	handler := gw.modeHandlers[GatewayModeOverlay]
	if handler == nil {
		t.Fatal("overlay handler is nil")
	}

	// Initially inactive
	if handler.IsActive() {
		t.Error("handler should not be active initially")
	}
	if handler.GetState() != nil {
		t.Error("state should be nil when inactive")
	}

	// Activate
	ctx := context.Background()
	if err := handler.Activate(ctx); err != nil {
		t.Fatalf("failed to activate: %v", err)
	}

	if !handler.IsActive() {
		t.Error("handler should be active after activation")
	}
	if handler.GetState() == nil {
		t.Error("state should not be nil when active")
	}

	// Activate again should fail
	if err := handler.Activate(ctx); err == nil {
		t.Error("expected error on double activation")
	}

	// Deactivate
	if err := handler.Deactivate(ctx); err != nil {
		t.Fatalf("failed to deactivate: %v", err)
	}

	if handler.IsActive() {
		t.Error("handler should not be active after deactivation")
	}

	// Deactivate again should fail
	if err := handler.Deactivate(ctx); err == nil {
		t.Error("expected error on double deactivation")
	}
}

func TestModeHandler_EdgeMode(t *testing.T) {
	// Use a config with a valid mode so it passes validation
	cfg := validConfig()

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	handler := gw.modeHandlers[GatewayModeEdge]
	if handler == nil {
		t.Fatal("edge handler is nil")
	}

	ctx := context.Background()

	// Activate
	if err := handler.Activate(ctx); err != nil {
		t.Fatalf("failed to activate: %v", err)
	}

	if !handler.IsActive() {
		t.Error("handler should be active")
	}

	state := handler.GetState()
	if state == nil {
		t.Error("state should not be nil")
	}

	_, ok := state.(*EdgeGatewayState)
	if !ok {
		t.Errorf("state type = %T, want *EdgeGatewayState", state)
	}

	// Deactivate
	if err := handler.Deactivate(ctx); err != nil {
		t.Fatalf("failed to deactivate: %v", err)
	}
}

func TestModeHandler_TransitMode(t *testing.T) {
	// Use a config with a valid mode so it passes validation
	cfg := validConfig()

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	handler := gw.modeHandlers[GatewayModeTransit]
	if handler == nil {
		t.Fatal("transit handler is nil")
	}

	ctx := context.Background()

	// Activate
	if err := handler.Activate(ctx); err != nil {
		t.Fatalf("failed to activate: %v", err)
	}

	if !handler.IsActive() {
		t.Error("handler should be active")
	}

	state := handler.GetState()
	if state == nil {
		t.Error("state should not be nil")
	}

	_, ok := state.(*TransitGatewayState)
	if !ok {
		t.Errorf("state type = %T, want *TransitGatewayState", state)
	}

	// Deactivate
	if err := handler.Deactivate(ctx); err != nil {
		t.Fatalf("failed to deactivate: %v", err)
	}
}

func TestGateway_StopCleansUpModes(t *testing.T) {
	cfg := validConfig()
	cfg.Modes = []GatewayMode{GatewayModeOverlay, GatewayModeEdge}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}

	// Verify modes are active
	if !gw.HasMode(GatewayModeOverlay) || !gw.HasMode(GatewayModeEdge) {
		t.Error("modes should be active before stop")
	}

	// Stop should deactivate all modes
	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("failed to stop gateway: %v", err)
	}

	// Verify modes are inactive
	if gw.HasMode(GatewayModeOverlay) || gw.HasMode(GatewayModeEdge) {
		t.Error("modes should be inactive after stop")
	}
}

func TestGateway_ConcurrentOperations(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Concurrent reads should be safe
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				_ = gw.GetStatus()
				_ = gw.IsRunning()
				_ = gw.GetActiveModes()
				_ = gw.GetNode()
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFormatHelpers(t *testing.T) {
	// Test formatPercent
	tests := []struct {
		input    float64
		expected string
	}{
		{95.0, "95.0%"},
		{99.9, "99.9%"},
		{0.0, "0.0%"},
		{100.0, "100.0%"},
	}

	for _, tt := range tests {
		result := formatPercent(tt.input)
		if result != tt.expected {
			t.Errorf("formatPercent(%v) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGateway_DisabledConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled: false,
		ID:      "", // Empty ID is OK when disabled
		Modes:   nil,
	}

	// Validation should pass for disabled config
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should pass validation: %v", err)
	}

	// But we still need valid config to create gateway
	cfg.Enabled = true
	cfg.ID = "test"
	cfg.Modes = []GatewayMode{GatewayModeOverlay}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	if gw.GetConfig().ID != "test" {
		t.Error("config ID not set correctly")
	}
}

func TestGateway_DeactivateModeNotActive(t *testing.T) {
	cfg := validConfig()
	cfg.Modes = []GatewayMode{GatewayModeOverlay}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("failed to start gateway: %v", err)
	}
	defer gw.Stop(ctx)

	// Try to deactivate a mode that was never activated
	err = gw.DeactivateMode(ctx, GatewayModeEdge)
	if err == nil {
		t.Error("expected error when deactivating mode that is not active")
	}

	var modeErr *ErrModeNotActive
	if !errors.As(err, &modeErr) {
		t.Errorf("expected ErrModeNotActive, got %T: %v", err, err)
	}
}

func TestGateway_ActivateModeNotRunning(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	ctx := context.Background()

	// Try to activate mode when gateway is stopped
	err = gw.ActivateMode(ctx, GatewayModeEdge)
	if err == nil {
		t.Error("expected error when activating mode on stopped gateway")
	}
	if !errors.Is(err, ErrGatewayNotRunning) {
		t.Errorf("expected ErrGatewayNotRunning, got %v", err)
	}
}

func TestGateway_DeactivateModeNotRunning(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	ctx := context.Background()

	// Try to deactivate mode when gateway is stopped
	err = gw.DeactivateMode(ctx, GatewayModeOverlay)
	if err == nil {
		t.Error("expected error when deactivating mode on stopped gateway")
	}
	if !errors.Is(err, ErrGatewayNotRunning) {
		t.Errorf("expected ErrGatewayNotRunning, got %v", err)
	}
}

func TestGateway_MeetsRequirementsWithCustomThresholds(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "test-gateway",
		Modes:         []GatewayMode{GatewayModeOverlay},
		MinReputation: 0.90, // Higher than default
		MinAgeDays:    200,  // Higher than default
		MinUptimePct:  98.0, // Higher than default
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	// Set metrics that meet default but not custom requirements
	gw.SetNodeMetrics(0.88, 180*24*time.Hour, 96.0)

	err = gw.MeetsRequirements()
	if err == nil {
		t.Error("expected error when metrics don't meet custom thresholds")
	}

	var reqErr *ErrRequirementsNotMet
	if !errors.As(err, &reqErr) {
		t.Errorf("expected ErrRequirementsNotMet, got %T: %v", err, err)
	}

	// Verify there are multiple failed checks
	if len(reqErr.Checks) == 0 {
		t.Error("expected failed checks in error")
	}
}

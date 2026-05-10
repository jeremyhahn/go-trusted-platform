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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// validConfig returns a valid gateway configuration for testing with overlay enabled.
func validConfig() *GatewayConfig {
	return &GatewayConfig{
		Enabled:       true,
		ID:            "test-gateway",
		NodeID:        12345,
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: true},
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
			name:        "valid config with overlay",
			config:      validConfig(),
			expectError: nil,
		},
		{
			name:        "nil config",
			config:      nil,
			expectError: ErrConfigNil,
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
		{
			name: "valid config - no services enabled",
			config: &GatewayConfig{
				Enabled:       true,
				ID:            "gw-no-services",
				MinReputation: MinReputation,
				MinAgeDays:    MinAgeDays,
				MinUptimePct:  MinUptimePct,
			},
			expectError: nil,
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
					if err.Error() != tt.expectError.Error() {
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

func TestGateway_ConfigDrivenServiceLoading(t *testing.T) {
	// Config with overlay enabled
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "test-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: true},
	}

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

	// Verify overlay service is active
	if !gw.HasService(ServiceOverlay) {
		t.Error("overlay service should be active")
	}

	// Verify edge service is NOT active (not in config)
	if gw.HasService(ServiceEdge) {
		t.Error("edge service should not be active")
	}

	// Verify transit service is NOT active (not in config)
	if gw.HasService(ServiceTransit) {
		t.Error("transit service should not be active")
	}
}

func TestGateway_MissingConfigSectionNotStarted(t *testing.T) {
	// Config with no service sections
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "empty-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
	}

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

	// No services should be active
	services := gw.ActiveServices()
	if len(services) != 0 {
		t.Errorf("expected 0 active services, got %d: %v", len(services), services)
	}
}

func TestGateway_EnabledFalseNotStarted(t *testing.T) {
	// Config with overlay present but disabled
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "disabled-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: false},
		Edge:          &EdgeConfig{Enabled: false, MaxDevices: 100, MaxServices: 50},
	}

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

	// No services should be active since enabled:false
	if gw.HasService(ServiceOverlay) {
		t.Error("overlay service should not be active when disabled")
	}
	if gw.HasService(ServiceEdge) {
		t.Error("edge service should not be active when disabled")
	}
}

func TestGateway_MultipleServicesConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "multi-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: true},
		Edge:          &EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50},
		BGP:           &bgp.BGPConfig{},
	}

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

	// All three services should be active
	if !gw.HasService(ServiceOverlay) {
		t.Error("overlay service should be active")
	}
	if !gw.HasService(ServiceEdge) {
		t.Error("edge service should be active")
	}
	if !gw.HasService(ServiceTransit) {
		t.Error("transit service should be active (BGP config present)")
	}

	// Verify status reports all services
	status := gw.GetStatus()
	if len(status.ActiveServiceNames) != 3 {
		t.Errorf("expected 3 active services, got %d", len(status.ActiveServiceNames))
	}
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

func TestGateway_GetStatus(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "status-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: true},
		Edge:          &EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50},
	}

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

func TestGateway_ActiveServices(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "active-svc-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: true},
		BGP:           &bgp.BGPConfig{},
	}

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

	services := gw.ActiveServices()
	if len(services) != 2 {
		t.Errorf("expected 2 active services, got %d: %v", len(services), services)
	}

	// Check overlay is present
	foundOverlay := false
	foundTransit := false
	for _, svc := range services {
		if svc == ServiceOverlay {
			foundOverlay = true
		}
		if svc == ServiceTransit {
			foundTransit = true
		}
	}
	if !foundOverlay {
		t.Error("should have overlay service")
	}
	if !foundTransit {
		t.Error("should have transit service")
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

func TestGateway_StopCleansUpServices(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "cleanup-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Overlay:       &OverlayServiceConfig{Enabled: true},
		Edge:          &EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50},
	}

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

	// Verify services are active
	if !gw.HasService(ServiceOverlay) || !gw.HasService(ServiceEdge) {
		t.Error("services should be active before stop")
	}

	// Stop should deactivate all services
	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("failed to stop gateway: %v", err)
	}

	// Verify services are inactive
	if gw.HasService(ServiceOverlay) || gw.HasService(ServiceEdge) {
		t.Error("services should be inactive after stop")
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
				_ = gw.ActiveServices()
				_ = gw.GetNode()
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFormatHelpers(t *testing.T) {
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
	}

	// Validation should pass for disabled config
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should pass validation: %v", err)
	}

	// But we still need valid config to create gateway
	cfg.Enabled = true
	cfg.ID = "test"
	cfg.Overlay = &OverlayServiceConfig{Enabled: true}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	if gw.GetConfig().ID != "test" {
		t.Error("config ID not set correctly")
	}
}

func TestGateway_MeetsRequirementsWithCustomThresholds(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "test-gateway",
		MinReputation: 0.90, // Higher than default
		MinAgeDays:    200,  // Higher than default
		MinUptimePct:  98.0, // Higher than default
		Overlay:       &OverlayServiceConfig{Enabled: true},
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

func TestServiceHandler_Overlay(t *testing.T) {
	cfg := validConfig()
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	handler, ok := gw.serviceHandlers[ServiceOverlay]
	if !ok {
		t.Fatal("overlay handler not registered")
	}

	if handler.Name() != ServiceOverlay {
		t.Errorf("Name() = %q, want %q", handler.Name(), ServiceOverlay)
	}

	// Initially inactive
	if handler.IsActive() {
		t.Error("handler should not be active initially")
	}

	// Start
	ctx := context.Background()
	if err := handler.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	if !handler.IsActive() {
		t.Error("handler should be active after start")
	}

	// Health should be OK
	if err := handler.Health(); err != nil {
		t.Errorf("health check failed: %v", err)
	}

	// Start again should fail
	if err := handler.Start(ctx); err == nil {
		t.Error("expected error on double start")
	}

	// Stop
	if err := handler.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}

	if handler.IsActive() {
		t.Error("handler should not be active after stop")
	}

	// Stop again should fail
	if err := handler.Stop(ctx); err == nil {
		t.Error("expected error on double stop")
	}
}

func TestServiceHandler_Edge(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "edge-test",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Edge:          &EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	handler, ok := gw.serviceHandlers[ServiceEdge]
	if !ok {
		t.Fatal("edge handler not registered")
	}

	if handler.Name() != ServiceEdge {
		t.Errorf("Name() = %q, want %q", handler.Name(), ServiceEdge)
	}

	ctx := context.Background()

	// Start
	if err := handler.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	if !handler.IsActive() {
		t.Error("handler should be active")
	}

	// Stop
	if err := handler.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}
}

func TestServiceHandler_Transit(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "transit-test",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		BGP:           &bgp.BGPConfig{},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	handler, ok := gw.serviceHandlers[ServiceTransit]
	if !ok {
		t.Fatal("transit handler not registered")
	}

	if handler.Name() != ServiceTransit {
		t.Errorf("Name() = %q, want %q", handler.Name(), ServiceTransit)
	}

	ctx := context.Background()

	// Start
	if err := handler.Start(ctx); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	if !handler.IsActive() {
		t.Error("handler should be active")
	}

	// Stop
	if err := handler.Stop(ctx); err != nil {
		t.Fatalf("failed to stop: %v", err)
	}
}

func TestGateway_TunnelConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "tunnel-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Tunnels: []TunnelConfig{
			{
				Name:     "gre1",
				Type:     "gre",
				Local:    "99.12.246.36",
				Remote:   "45.63.110.165",
				TunnelIP: "10.255.0.1",
			},
		},
	}

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

	if !gw.HasService(ServiceTunnels) {
		t.Error("tunnel service should be active")
	}
}

func TestGateway_FirewallConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "fw-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		Firewall:      &FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
	}

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

	if !gw.HasService(ServiceFirewall) {
		t.Error("firewall service should be active")
	}
}

func TestGateway_DHCPConfig(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "dhcp-gw",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		DHCP:          &DHCPServiceConfig{Enabled: true, Interface: "eth0"},
	}

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

	if !gw.HasService(ServiceDHCP) {
		t.Error("DHCP service should be active")
	}
}

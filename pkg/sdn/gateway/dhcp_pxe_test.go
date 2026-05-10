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
	"testing"
	"time"
)

func TestDHCPServiceHandler_StartStop(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-dhcp-test",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		DHCP: &DHCPServiceConfig{
			Enabled:   true,
			Interface: "bond0.201",
			Segment:   "provisioning",
		},
	}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating gateway: %v", err)
	}

	handler, ok := gw.serviceHandlers[ServiceDHCP]
	if !ok {
		t.Fatal("expected DHCP service handler to be registered")
	}

	if handler.Name() != ServiceDHCP {
		t.Errorf("expected handler name %q, got %q", ServiceDHCP, handler.Name())
	}

	if handler.IsActive() {
		t.Error("expected handler to be inactive before start")
	}

	ctx := context.Background()
	if err := handler.Start(ctx); err != nil {
		t.Fatalf("unexpected error starting DHCP handler: %v", err)
	}

	if !handler.IsActive() {
		t.Error("expected handler to be active after start")
	}

	if err := handler.Health(); err != nil {
		t.Errorf("unexpected health check error: %v", err)
	}

	// Double start returns error
	if err := handler.Start(ctx); err == nil {
		t.Error("expected error on double start")
	}

	if err := handler.Stop(ctx); err != nil {
		t.Fatalf("unexpected error stopping DHCP handler: %v", err)
	}

	if handler.IsActive() {
		t.Error("expected handler to be inactive after stop")
	}

	// Double stop returns error
	if err := handler.Stop(ctx); err == nil {
		t.Error("expected error on double stop")
	}
}

func TestDHCPServiceHandler_NotRegisteredWhenDisabled(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-dhcp-disabled",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		DHCP: &DHCPServiceConfig{
			Enabled:   false,
			Interface: "bond0.201",
		},
	}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating gateway: %v", err)
	}

	if _, ok := gw.serviceHandlers[ServiceDHCP]; ok {
		t.Error("DHCP handler should not be registered when disabled")
	}
}

func TestDHCPServiceConfig_ValidateWithSegment(t *testing.T) {
	tests := []struct {
		name      string
		config    *DHCPServiceConfig
		expectErr bool
	}{
		{
			name: "valid with interface",
			config: &DHCPServiceConfig{
				Enabled:   true,
				Interface: "bond0.201",
			},
			expectErr: false,
		},
		{
			name: "valid with segment",
			config: &DHCPServiceConfig{
				Enabled:   true,
				Interface: "bond0.201",
				Segment:   "provisioning",
			},
			expectErr: false,
		},
		{
			name: "disabled is always valid",
			config: &DHCPServiceConfig{
				Enabled: false,
			},
			expectErr: false,
		},
		{
			name: "invalid missing interface",
			config: &DHCPServiceConfig{
				Enabled: true,
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectErr && err == nil {
				t.Error("expected validation error")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestPXEServiceHandler_StartStop(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-pxe-test",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		PXE: &PXEServiceConfig{
			Enabled:         true,
			HTTPPort:        8069,
			TFTPPort:        69,
			ConfigServerURL: "https://cp.example.com:8443/api/v1/devices/config",
		},
	}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating gateway: %v", err)
	}

	handler, ok := gw.serviceHandlers[ServicePXE]
	if !ok {
		t.Fatal("expected PXE service handler to be registered")
	}

	if handler.Name() != ServicePXE {
		t.Errorf("expected handler name %q, got %q", ServicePXE, handler.Name())
	}

	if handler.IsActive() {
		t.Error("expected handler to be inactive before start")
	}

	ctx := context.Background()
	if err := handler.Start(ctx); err != nil {
		t.Fatalf("unexpected error starting PXE handler: %v", err)
	}

	if !handler.IsActive() {
		t.Error("expected handler to be active after start")
	}

	if err := handler.Health(); err != nil {
		t.Errorf("unexpected health check error: %v", err)
	}

	// Double start returns error
	if err := handler.Start(ctx); err == nil {
		t.Error("expected error on double start")
	}

	if err := handler.Stop(ctx); err != nil {
		t.Fatalf("unexpected error stopping PXE handler: %v", err)
	}

	if handler.IsActive() {
		t.Error("expected handler to be inactive after stop")
	}

	// Double stop returns error
	if err := handler.Stop(ctx); err == nil {
		t.Error("expected error on double stop")
	}
}

func TestPXEServiceHandler_NotRegisteredWhenDisabled(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-pxe-disabled",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		PXE: &PXEServiceConfig{
			Enabled: false,
		},
	}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating gateway: %v", err)
	}

	if _, ok := gw.serviceHandlers[ServicePXE]; ok {
		t.Error("PXE handler should not be registered when disabled")
	}
}

func TestPXEServiceConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *PXEServiceConfig
		expectErr bool
	}{
		{
			name: "valid config",
			config: &PXEServiceConfig{
				Enabled:         true,
				HTTPPort:        8069,
				TFTPPort:        69,
				ConfigServerURL: "https://cp.example.com:8443/api/v1/devices/config",
			},
			expectErr: false,
		},
		{
			name: "disabled is always valid",
			config: &PXEServiceConfig{
				Enabled: false,
			},
			expectErr: false,
		},
		{
			name: "invalid missing http port",
			config: &PXEServiceConfig{
				Enabled: true,
			},
			expectErr: true,
		},
		{
			name: "invalid negative http port",
			config: &PXEServiceConfig{
				Enabled:  true,
				HTTPPort: -1,
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectErr && err == nil {
				t.Error("expected validation error")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestGatewayConfig_HasEnabledServices_PXE(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-pxe-services",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		PXE: &PXEServiceConfig{
			Enabled:  true,
			HTTPPort: 8069,
		},
	}

	if !cfg.HasEnabledServices() {
		t.Error("expected HasEnabledServices to return true with PXE enabled")
	}
}

func TestGateway_DHCPAndPXETogether(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-dhcp-pxe",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		DHCP: &DHCPServiceConfig{
			Enabled:       true,
			Interface:     "bond0.201",
			Segment:       "provisioning",
			PoolStart:     "10.201.0.50",
			PoolEnd:       "10.201.0.254",
			LeaseDuration: 1 * time.Hour,
		},
		PXE: &PXEServiceConfig{
			Enabled:           true,
			HTTPPort:          8069,
			TFTPPort:          69,
			ConfigServerURL:   "https://cp.trusted-platform.io:8443/api/v1/devices/config",
			BootstrapStrategy: "dane",
		},
	}

	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating gateway: %v", err)
	}

	if _, ok := gw.serviceHandlers[ServiceDHCP]; !ok {
		t.Error("DHCP handler should be registered")
	}
	if _, ok := gw.serviceHandlers[ServicePXE]; !ok {
		t.Error("PXE handler should be registered")
	}

	// Set metrics to pass requirements
	rep, age, uptime := validNodeMetrics()
	gw.SetNodeMetrics(rep, age, uptime)

	ctx := context.Background()
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("unexpected error starting gateway: %v", err)
	}

	if !gw.HasService(ServiceDHCP) {
		t.Error("DHCP service should be active")
	}
	if !gw.HasService(ServicePXE) {
		t.Error("PXE service should be active")
	}

	if err := gw.Stop(ctx); err != nil {
		t.Fatalf("unexpected error stopping gateway: %v", err)
	}
}

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
	"strings"
	"testing"
)

// TestDHCPServiceHandler_IsRefused: the DHCP section is enabled but gatewayd
// has no IPAM allocator to serve leases from, so the handler is a typed
// refusal, never a service that reports running (#568).
func TestDHCPServiceHandler_IsRefused(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-dhcp-test",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		DHCP: &DHCPServiceConfig{
			Enabled:   true,
			Interface: "zone405",
			Zone:      "provisioning",
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
		t.Error("a refused service never reports active")
	}
	var unavailable *ErrServiceUnavailable
	if err := handler.Start(context.Background()); !errors.As(err, &unavailable) {
		t.Fatalf("Start = %v, want ErrServiceUnavailable", err)
	}
	if unavailable.Service != ServiceDHCP || !strings.Contains(unavailable.Reason, "IPAM") {
		t.Errorf("refusal = %+v, want the dhcp section and the missing allocator named", unavailable)
	}
	if handler.IsActive() {
		t.Error("a refused Start leaves the handler inactive")
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
			name: "valid with zone",
			config: &DHCPServiceConfig{
				Enabled:   true,
				Interface: "zone405",
				Zone:      "provisioning",
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

// TestPXEServiceHandler_IsRefused: the PXE section is enabled but the PXE
// controller needs a serving interface, address and DHCP range the section
// does not carry, so the handler is a typed refusal (#568).
func TestPXEServiceHandler_IsRefused(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-pxe-test",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		PXE: &PXEServiceConfig{
			Enabled:  true,
			HTTPPort: 8069,
			TFTPPort: 69,
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
	if handler.IsActive() {
		t.Error("a refused service never reports active")
	}
	var unavailable *ErrServiceUnavailable
	if err := handler.Start(context.Background()); !errors.As(err, &unavailable) {
		t.Fatalf("Start = %v, want ErrServiceUnavailable", err)
	}
	if unavailable.Service != ServicePXE {
		t.Errorf("refusal names %q, want %q", unavailable.Service, ServicePXE)
	}
	if err := handler.Health(); !errors.As(err, &unavailable) {
		t.Errorf("Health = %v, want the refusal", err)
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

// TestGateway_DHCPAndPXETogether: two refused sections fail the gateway
// start with the first refusal in declared order, and nothing is left
// active.
func TestGateway_DHCPAndPXETogether(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "gw-dhcp-pxe",
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
		DHCP:          &DHCPServiceConfig{Enabled: true, Interface: "zone405", Zone: "provisioning"},
		PXE:           &PXEServiceConfig{Enabled: true, HTTPPort: 8069},
	}
	gw, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating gateway: %v", err)
	}
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var unavailable *ErrServiceUnavailable
	if !errors.As(err, &unavailable) {
		t.Fatalf("Start = %v, want ErrServiceUnavailable", err)
	}
	if unavailable.Service != ServiceDHCP {
		t.Errorf("first refusal = %q, want dhcp (declared before pxe)", unavailable.Service)
	}
	if len(gw.ActiveServices()) != 0 {
		t.Errorf("nothing may be active after a refused start, got %v", gw.ActiveServices())
	}
	snap := gw.Snapshot()
	if snap.DHCP.Status != "stopped" || snap.PXE.Status != "stopped" {
		t.Errorf("snapshot must not report refused services running: dhcp=%q pxe=%q", snap.DHCP.Status, snap.PXE.Status)
	}
}

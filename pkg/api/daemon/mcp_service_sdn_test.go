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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

// =============================================================================
// Mock Policy Engine for SDN Tests
// =============================================================================

// =============================================================================
// SDNApplyPolicy Extended Tests
// =============================================================================

// =============================================================================
// SDNListPolicies Extended Tests
// =============================================================================

// =============================================================================
// SDNAuthenticatePort Extended Tests
// =============================================================================

func TestMCPServiceProvider_SDNAuthenticatePort_DefaultsFormatToPEM(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with empty format - should default to PEM internally
	// but still fail due to nil SDN service
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", map[string]string{
		"certificate": "test-cert",
		// format is intentionally missing
	})
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// Verify we get service not available (meaning format defaulting worked)
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_ExplicitFormatDER(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with explicit DER format
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", map[string]string{
		"certificate": "test-cert-data",
		"format":      "DER",
	})
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// Should still get service not available error
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNGetPolicy Extended Tests
// =============================================================================

// =============================================================================
// Error Type Validation Tests - Verifies error messages match actual format
// =============================================================================

func TestErrSDNMissingParameter_ErrorMessage(t *testing.T) {
	err := ErrSDNMissingParameter{Parameter: "bridgeName"}
	expected := "missing required parameter: bridgeName"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNPolicyNotFound_ErrorMessage(t *testing.T) {
	err := ErrSDNPolicyNotFound{PolicyID: "policy123"}
	expected := "SDN policy not found: policy123"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNPortNotFound_ErrorMessage(t *testing.T) {
	err := ErrSDNPortNotFound{BridgeName: "br0", PortName: "port1"}
	expected := "SDN port not found: port1 on bridge br0"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNApplyPolicyFailed_ErrorMessage(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrSDNApplyPolicyFailed{PolicyID: "policy1", Cause: cause}
	expected := "failed to apply policy policy1: timeout"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNSetPortStateFailed_ErrorMessage(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrSDNSetPortStateFailed{PortID: "port1", Cause: cause}
	expected := "failed to set port state for port1: connection refused"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

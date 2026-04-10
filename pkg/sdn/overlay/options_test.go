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

package overlay

import (
	"log/slog"
	"net/netip"
	"testing"
)

func TestWithLogger(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	logger := slog.Default()

	ctrl, err := New(config, WithLogger(logger))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.logger != logger {
		t.Errorf("WithLogger() did not set logger correctly")
	}
}

func TestWithStateManager(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	stateManager := NewStateManager()

	ctrl, err := New(config, WithStateManager(stateManager))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.state != stateManager {
		t.Errorf("WithStateManager() did not set state manager correctly")
	}
}

func TestWithOVSClient(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil OVS client (just verifies the option function works)
	ctrl, err := New(config, WithOVSClient(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.ovsClient != nil {
		t.Errorf("WithOVSClient(nil) should set ovsClient to nil")
	}
}

func TestWithOpenFlowClient(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil OpenFlow client (just verifies the option function works)
	ctrl, err := New(config, WithOpenFlowClient(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.ofClient != nil {
		t.Errorf("WithOpenFlowClient(nil) should set ofClient to nil")
	}
}

func TestWithVTEPManager(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil VTEP manager (just verifies the option function works)
	ctrl, err := New(config, WithVTEPManager(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.vtepManager != nil {
		t.Errorf("WithVTEPManager(nil) should set vtepManager to nil")
	}
}

func TestWithBGPSpeaker(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil BGP speaker (just verifies the option function works)
	ctrl, err := New(config, WithBGPSpeaker(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.bgpSpeaker != nil {
		t.Errorf("WithBGPSpeaker(nil) should set bgpSpeaker to nil")
	}
}

func TestWithEVPNManager(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil EVPN manager (just verifies the option function works)
	ctrl, err := New(config, WithEVPNManager(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.evpnManager != nil {
		t.Errorf("WithEVPNManager(nil) should set evpnManager to nil")
	}
}

func TestWithGateway(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil gateway (just verifies the option function works)
	ctrl, err := New(config, WithGateway(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.gateway != nil {
		t.Errorf("WithGateway(nil) should set gateway to nil")
	}
}

func TestWithIPAM(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	// Test with nil IPAM (just verifies the option function works)
	ctrl, err := New(config, WithIPAM(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ctrl.ipam != nil {
		t.Errorf("WithIPAM(nil) should set ipam to nil")
	}
}

func TestMultipleOptions(t *testing.T) {
	t.Parallel()

	config := &Config{
		NodeID:            "test-node",
		VTEPIP:            netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface: "eth0",
		BridgeName:        "br-test",
	}

	logger := slog.Default()
	stateManager := NewStateManager()

	ctrl, err := New(config,
		WithLogger(logger),
		WithStateManager(stateManager),
		WithOVSClient(nil),
		WithOpenFlowClient(nil),
		WithVTEPManager(nil),
		WithBGPSpeaker(nil),
		WithEVPNManager(nil),
		WithGateway(nil),
		WithIPAM(nil),
	)
	if err != nil {
		t.Fatalf("New() with multiple options error = %v", err)
	}

	if ctrl.logger != logger {
		t.Errorf("WithLogger() did not set logger")
	}
	if ctrl.state != stateManager {
		t.Errorf("WithStateManager() did not set state manager")
	}
}

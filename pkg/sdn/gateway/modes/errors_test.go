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
	"errors"
	"net"
	"net/netip"
	"testing"
)

// TestSentinelErrors_OverlayMode tests all overlay mode sentinel error types.
func TestSentinelErrors_OverlayMode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrConfigNil", ErrConfigNil, "configuration is nil"},
		{"ErrAlreadyRunning", ErrAlreadyRunning, "handler already running"},
		{"ErrNotRunning", ErrNotRunning, "handler not running"},
		{"ErrVTEPConfigNil", ErrVTEPConfigNil, "VTEP configuration is nil"},
		{"ErrBridgeNameEmpty", ErrBridgeNameEmpty, "bridge name is empty"},
		{"ErrLoggerNil", ErrLoggerNil, "logger is nil"},
		{"ErrOVSClientNil", ErrOVSClientNil, "OVS client is nil"},
		{"ErrOpenFlowClientNil", ErrOpenFlowClientNil, "OpenFlow client is nil"},
		{"ErrVNIOutOfRange", ErrVNIOutOfRange, "VNI must be between 1 and 16777215"},
		{"ErrVLANOutOfRange", ErrVLANOutOfRange, "VLAN ID must be between 1 and 4094"},
		{"ErrVNIAlreadyExists", ErrVNIAlreadyExists, "VNI already exists"},
		{"ErrVNINotFound", ErrVNINotFound, "VNI not found"},
		{"ErrMACNil", ErrMACNil, "MAC address is nil"},
		{"ErrMACInvalid", ErrMACInvalid, "MAC address must be 6 bytes"},
		{"ErrMACNotFound", ErrMACNotFound, "MAC address not found"},
		{"ErrInvalidVTEPIP", ErrInvalidVTEPIP, "invalid VTEP IP address"},
		{"ErrAccessPortEmpty", ErrAccessPortEmpty, "access port is empty"},
		{"ErrAccessPortUnresolved", ErrAccessPortUnresolved, "access port has no OpenFlow port number"},
		{"ErrSwitchNotRestored", ErrSwitchNotRestored, "overlay ports not resolved since the switch reconnected"},
		{"ErrVLANInUse", ErrVLANInUse, "VLAN already carries another VNI"},
		{"ErrAnycastGatewayIncomplete", ErrAnycastGatewayIncomplete, "anycast gateway needs both an IPv4 address and a MAC"},
		{"ErrAnycastGatewayRequired", ErrAnycastGatewayRequired, "an L3VNI needs the anycast gateway to route into it"},
		{"ErrRouterMACRequired", ErrRouterMACRequired, "an L3VNI needs the EVPN router MAC for symmetric IRB"},
		{"ErrFlowNotTracked", ErrFlowNotTracked, "overlay flow is not installed"},
		{"ErrAdmitterNil", ErrAdmitterNil, "EVPN needs a VTEP admitter to vet the VTEPs its routes name"},
		{"ErrVTEPRevoked", ErrVTEPRevoked, "the VTEP was revoked while its route was being admitted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

// TestContextualErrors_OverlayMode tests overlay mode contextual error types.
func TestContextualErrors_OverlayMode(t *testing.T) {
	t.Run("ErrStopFailed", func(t *testing.T) {
		cause := errors.New("stop error")
		err := &ErrStopFailed{Component: "EVPNManager", Cause: cause}
		if got := err.Error(); got != "failed to stop EVPNManager: stop error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrOverlayInitFailed", func(t *testing.T) {
		cause := errors.New("vtep error")
		err := &ErrOverlayInitFailed{Component: "VTEPManager", Cause: cause}
		if got := err.Error(); got != "overlay initialization failed for VTEPManager: vtep error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrOverlayStartFailed", func(t *testing.T) {
		cause := errors.New("start error")
		err := &ErrOverlayStartFailed{Component: "EVPNManager", Cause: cause}
		if got := err.Error(); got != "overlay start failed for EVPNManager: start error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrOverlayPortUnresolved", func(t *testing.T) {
		err := &ErrOverlayPortUnresolved{Port: "AccessPort", Cause: ErrAccessPortUnresolved}
		if got := err.Error(); got != "resolving the overlay AccessPort: access port has no OpenFlow port number" {
			t.Errorf("Error() = %q", got)
		}
		if !errors.Is(err, ErrAccessPortUnresolved) {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrVNIOperationFailed", func(t *testing.T) {
		cause := errors.New("flow error")
		err := &ErrVNIOperationFailed{VNI: 1000, Operation: "add", Cause: cause}
		if got := err.Error(); got != "VNI 1000 add failed: flow error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrMACOperationFailed", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		cause := errors.New("mac error")
		err := &ErrMACOperationFailed{MAC: mac, Operation: "learn", Cause: cause}
		if got := err.Error(); got != "MAC aa:bb:cc:dd:ee:ff learn failed: mac error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrVTEPOperationFailed", func(t *testing.T) {
		vtepIP := netip.MustParseAddr("10.0.0.2")
		cause := errors.New("tunnel error")
		err := &ErrVTEPOperationFailed{VTEPIP: vtepIP, Operation: "add-tunnel", Cause: cause}
		if got := err.Error(); got != "VTEP 10.0.0.2 add-tunnel failed: tunnel error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrFlowOperationFailed", func(t *testing.T) {
		cause := errors.New("openflow error")
		err := &ErrFlowOperationFailed{Table: 30, Operation: "install", Cause: cause}
		if got := err.Error(); got != "flow install on table 30 failed: openflow error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrFlowResyncFailed", func(t *testing.T) {
		cause := errors.New("openflow error")
		err := &ErrFlowResyncFailed{Cause: cause}
		if got := err.Error(); got != "restoring the overlay flows after a failed change failed: openflow error" {
			t.Errorf("Error() = %q", got)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("ErrBindingConflict", func(t *testing.T) {
		err := &ErrBindingConflict{
			VNI:   10100,
			MAC:   net.HardwareAddr{0x02, 0, 0, 0, 0x02, 0x20},
			IP:    netip.MustParseAddr("10.1.0.1"),
			Owner: "anycast gateway IP",
		}
		want := "remote binding 02:00:00:00:02:20 10.1.0.1 on VNI 10100 conflicts with the anycast gateway IP"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q", got)
		}
	})
}

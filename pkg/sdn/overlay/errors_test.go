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
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err     error
		message string
	}{
		{ErrControllerNotRunning, "overlay controller not running"},
		{ErrControllerAlreadyRunning, "overlay controller already running"},
		{ErrConfigNil, "configuration is nil"},
		{ErrNodeIDEmpty, "node ID is empty"},
		{ErrInvalidVTEPIP, "invalid VTEP IP address"},
		{ErrUnderlayInterfaceEmpty, "underlay interface name is empty"},
		{ErrMTUTooSmall, "MTU too small for VXLAN encapsulation"},
		{ErrInvalidVXLANPort, "invalid VXLAN port"},
		{ErrBridgeNameEmpty, "bridge name is empty"},
		{ErrVTEPNotFound, "VTEP not found"},
		{ErrVTEPAlreadyExists, "VTEP already exists"},
		{ErrTunnelNotFound, "tunnel not found"},
		{ErrTunnelAlreadyExists, "tunnel already exists"},
		{ErrVNINotFound, "VNI not found"},
		{ErrVNIAlreadyExists, "VNI already exists"},
		{ErrVNIOutOfRange, "VNI out of valid range (1-16777215)"},
		{ErrVLANOutOfRange, "VLAN out of valid range (0-4094)"},
		{ErrMACNotFound, "MAC entry not found"},
		{ErrMACAlreadyExists, "MAC entry already exists"},
		{ErrOVSClientNil, "OVS client is nil"},
		{ErrVTEPManagerNil, "VTEP manager is nil"},
		{ErrBGPServiceNil, "BGP service is nil"},
		{ErrIPAMNil, "IPAM allocator is nil"},
		{ErrLoggerNil, "logger is nil"},
		{ErrShutdownTimeout, "shutdown timeout exceeded"},
		{ErrStateBackendUnsupported, "state backend not supported"},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.message {
				t.Errorf("Error() = %v, want %v", got, tt.message)
			}
		})
	}
}

func TestErrStartupFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrStartupFailed{
			NodeID: "node1",
			Phase:  "initialization",
			Cause:  cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "node1") {
			t.Errorf("Error() missing NodeID")
		}
		if !strings.Contains(msg, "initialization") {
			t.Errorf("Error() missing Phase")
		}
		if !strings.Contains(msg, "underlying error") {
			t.Errorf("Error() missing Cause")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrStartupFailed{
			NodeID: "node1",
			Phase:  "initialization",
		}

		msg := err.Error()
		if !strings.Contains(msg, "node1") {
			t.Errorf("Error() missing NodeID")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrShutdownFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrShutdownFailed{
			NodeID: "node1",
			Phase:  "cleanup",
			Cause:  cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "node1") {
			t.Errorf("Error() missing NodeID")
		}
		if !strings.Contains(msg, "cleanup") {
			t.Errorf("Error() missing Phase")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrShutdownFailed{
			NodeID: "node1",
			Phase:  "cleanup",
		}

		msg := err.Error()
		if !strings.Contains(msg, "node1") {
			t.Errorf("Error() missing NodeID")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrVNIOperationFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrVNIOperationFailed{
			VNI:       100000,
			Operation: "add",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "100000") {
			t.Errorf("Error() missing VNI")
		}
		if !strings.Contains(msg, "add") {
			t.Errorf("Error() missing Operation")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrVNIOperationFailed{
			VNI:       100000,
			Operation: "add",
		}

		msg := err.Error()
		if !strings.Contains(msg, "100000") {
			t.Errorf("Error() missing VNI")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrTunnelOperationFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrTunnelOperationFailed{
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			VNI:        100000,
			Operation:  "create",
			Cause:      cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "10.0.0.2") {
			t.Errorf("Error() missing RemoteVTEP")
		}
		if !strings.Contains(msg, "100000") {
			t.Errorf("Error() missing VNI")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrTunnelOperationFailed{
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			VNI:        100000,
			Operation:  "create",
		}

		msg := err.Error()
		if !strings.Contains(msg, "10.0.0.2") {
			t.Errorf("Error() missing RemoteVTEP")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrMACOperationFailed(t *testing.T) {
	t.Parallel()

	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrMACOperationFailed{
			MAC:       mac,
			VNI:       100000,
			Operation: "learn",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "00:11:22:33:44:55") {
			t.Errorf("Error() missing MAC")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrMACOperationFailed{
			MAC:       mac,
			VNI:       100000,
			Operation: "learn",
		}

		msg := err.Error()
		if !strings.Contains(msg, "00:11:22:33:44:55") {
			t.Errorf("Error() missing MAC")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrBGPOperationFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrBGPOperationFailed{
			Operation: "announce",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "announce") {
			t.Errorf("Error() missing Operation")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrBGPOperationFailed{
			Operation: "announce",
		}

		msg := err.Error()
		if !strings.Contains(msg, "announce") {
			t.Errorf("Error() missing Operation")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrOVSOperationFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrOVSOperationFailed{
			Bridge:    "br-overlay",
			Operation: "add-port",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "br-overlay") {
			t.Errorf("Error() missing Bridge")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrOVSOperationFailed{
			Bridge:    "br-overlay",
			Operation: "add-port",
		}

		msg := err.Error()
		if !strings.Contains(msg, "br-overlay") {
			t.Errorf("Error() missing Bridge")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrInvalidState(t *testing.T) {
	t.Parallel()

	err := &ErrInvalidState{
		Expected: ControllerStateStopped,
		Actual:   ControllerStateRunning,
	}

	msg := err.Error()
	if !strings.Contains(msg, "stopped") {
		t.Errorf("Error() missing Expected state")
	}
	if !strings.Contains(msg, "running") {
		t.Errorf("Error() missing Actual state")
	}
}

func TestErrInvalidMAC(t *testing.T) {
	t.Parallel()

	t.Run("with MAC", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		err := &ErrInvalidMAC{
			MAC:    mac,
			Reason: "broadcast address",
		}

		msg := err.Error()
		if !strings.Contains(msg, "00:11:22:33:44:55") {
			t.Errorf("Error() missing MAC")
		}
		if !strings.Contains(msg, "broadcast address") {
			t.Errorf("Error() missing Reason")
		}
	})

	t.Run("without MAC", func(t *testing.T) {
		err := &ErrInvalidMAC{
			MAC:    nil,
			Reason: "nil address",
		}

		msg := err.Error()
		if !strings.Contains(msg, "nil address") {
			t.Errorf("Error() missing Reason")
		}
	})
}

func TestErrInvalidIP(t *testing.T) {
	t.Parallel()

	t.Run("with valid IP", func(t *testing.T) {
		err := &ErrInvalidIP{
			IP:     netip.MustParseAddr("10.0.0.1"),
			Reason: "loopback not allowed",
		}

		msg := err.Error()
		if !strings.Contains(msg, "10.0.0.1") {
			t.Errorf("Error() missing IP")
		}
		if !strings.Contains(msg, "loopback not allowed") {
			t.Errorf("Error() missing Reason")
		}
	})

	t.Run("with invalid IP", func(t *testing.T) {
		err := &ErrInvalidIP{
			IP:     netip.Addr{},
			Reason: "empty address",
		}

		msg := err.Error()
		if !strings.Contains(msg, "empty address") {
			t.Errorf("Error() missing Reason")
		}
	})
}

func TestErrInvalidVNI(t *testing.T) {
	t.Parallel()

	err := &ErrInvalidVNI{
		VNI:    16777216,
		Reason: "exceeds maximum",
	}

	msg := err.Error()
	if !strings.Contains(msg, "16777216") {
		t.Errorf("Error() missing VNI")
	}
	if !strings.Contains(msg, "exceeds maximum") {
		t.Errorf("Error() missing Reason")
	}
}

func TestErrComponentNotInitialized(t *testing.T) {
	t.Parallel()

	err := &ErrComponentNotInitialized{
		Component: "BGPSpeaker",
	}

	msg := err.Error()
	if !strings.Contains(msg, "BGPSpeaker") {
		t.Errorf("Error() missing Component")
	}
}

func TestErrHealthCheckFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := &ErrHealthCheckFailed{
			Component: "OVS",
			Reason:    "connection failed",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "OVS") {
			t.Errorf("Error() missing Component")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("with reason only", func(t *testing.T) {
		err := &ErrHealthCheckFailed{
			Component: "OVS",
			Reason:    "connection failed",
		}

		msg := err.Error()
		if !strings.Contains(msg, "connection failed") {
			t.Errorf("Error() missing Reason")
		}
	})

	t.Run("component only", func(t *testing.T) {
		err := &ErrHealthCheckFailed{
			Component: "OVS",
		}

		msg := err.Error()
		if !strings.Contains(msg, "OVS") {
			t.Errorf("Error() missing Component")
		}
	})
}

func TestErrEVPNOperationFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("encoding failed")
		err := &ErrEVPNOperationFailed{
			RouteType: "Type-2",
			Operation: "advertise",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "Type-2") {
			t.Errorf("Error() missing RouteType")
		}
		if !strings.Contains(msg, "advertise") {
			t.Errorf("Error() missing Operation")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrEVPNOperationFailed{
			RouteType: "Type-2",
			Operation: "advertise",
		}

		msg := err.Error()
		if !strings.Contains(msg, "Type-2") {
			t.Errorf("Error() missing RouteType")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrVTEPOperationFailed(t *testing.T) {
	t.Parallel()

	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("unreachable")
		err := &ErrVTEPOperationFailed{
			VTEP:      netip.MustParseAddr("10.0.0.2"),
			Operation: "ping",
			Cause:     cause,
		}

		msg := err.Error()
		if !strings.Contains(msg, "10.0.0.2") {
			t.Errorf("Error() missing VTEP")
		}

		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrVTEPOperationFailed{
			VTEP:      netip.MustParseAddr("10.0.0.2"),
			Operation: "ping",
		}

		msg := err.Error()
		if !strings.Contains(msg, "10.0.0.2") {
			t.Errorf("Error() missing VTEP")
		}

		if err.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

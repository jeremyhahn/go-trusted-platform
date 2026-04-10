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

package vxlan

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{
			name: "ErrVNIOutOfRange",
			err:  ErrVNIOutOfRange,
			msg:  "VNI must be between 1 and 16777215",
		},
		{
			name: "ErrVNIInUse",
			err:  ErrVNIInUse,
			msg:  "VNI already in use",
		},
		{
			name: "ErrTunnelNotFound",
			err:  ErrTunnelNotFound,
			msg:  "tunnel not found",
		},
		{
			name: "ErrTunnelExists",
			err:  ErrTunnelExists,
			msg:  "tunnel already exists",
		},
		{
			name: "ErrVTEPNotConfigured",
			err:  ErrVTEPNotConfigured,
			msg:  "VTEP not configured",
		},
		{
			name: "ErrInvalidVTEPIP",
			err:  ErrInvalidVTEPIP,
			msg:  "invalid VTEP IP address",
		},
		{
			name: "ErrUnderlayNotReady",
			err:  ErrUnderlayNotReady,
			msg:  "underlay interface not ready",
		},
		{
			name: "ErrMTUTooSmall",
			err:  ErrMTUTooSmall,
			msg:  "MTU too small for VXLAN (minimum 1550)",
		},
		{
			name: "ErrInvalidVXLANPort",
			err:  ErrInvalidVXLANPort,
			msg:  "invalid VXLAN UDP port",
		},
		{
			name: "ErrVLANOutOfRange",
			err:  ErrVLANOutOfRange,
			msg:  "VLAN ID out of range (0-4094)",
		},
		{
			name: "ErrMappingNotFound",
			err:  ErrMappingNotFound,
			msg:  "VNI/VLAN mapping not found",
		},
		{
			name: "ErrManagerNotStarted",
			err:  ErrManagerNotStarted,
			msg:  "VTEP manager not started",
		},
		{
			name: "ErrManagerAlreadyStarted",
			err:  ErrManagerAlreadyStarted,
			msg:  "VTEP manager already started",
		},
		{
			name: "ErrInvalidTunnelID",
			err:  ErrInvalidTunnelID,
			msg:  "invalid tunnel ID",
		},
		{
			name: "ErrOVSClientNil",
			err:  ErrOVSClientNil,
			msg:  "OVS client is nil",
		},
		{
			name: "ErrBridgeNameEmpty",
			err:  ErrBridgeNameEmpty,
			msg:  "bridge name is empty",
		},
		{
			name: "ErrLoggerNil",
			err:  ErrLoggerNil,
			msg:  "logger is nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, tc.err)
			assert.Equal(t, tc.msg, tc.err.Error())
		})
	}
}

func TestErrTunnelCreationFailed(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := &ErrTunnelCreationFailed{
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			VNI:        1000100,
			Cause:      cause,
		}

		expectedMsg := "failed to create tunnel to 10.0.0.2 for VNI 1000100: connection refused"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrTunnelCreationFailed{
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			VNI:        1000100,
			Cause:      cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrTunnelDeletionFailed(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		cause := errors.New("port not found")
		err := &ErrTunnelDeletionFailed{
			TunnelID: "10.0.0.1-10.0.0.2-1000100",
			Cause:    cause,
		}

		expectedMsg := "failed to delete tunnel 10.0.0.1-10.0.0.2-1000100: port not found"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrTunnelDeletionFailed{
			TunnelID: "tunnel-1",
			Cause:    cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrVNIMappingFailed(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		cause := errors.New("VNI conflict")
		err := &ErrVNIMappingFailed{
			VLAN:  100,
			VNI:   1000100,
			Cause: cause,
		}

		expectedMsg := "failed to map VLAN 100 to VNI 1000100: VNI conflict"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrVNIMappingFailed{
			VLAN:  100,
			VNI:   1000100,
			Cause: cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrOVSOperationFailed(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		cause := errors.New("socket timeout")
		err := &ErrOVSOperationFailed{
			Operation: "add_port",
			Target:    "vxlan-abc123",
			Cause:     cause,
		}

		expectedMsg := "OVS add_port operation failed for vxlan-abc123: socket timeout"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrOVSOperationFailed{
			Operation: "delete",
			Target:    "port-1",
			Cause:     cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrVTEPValidationFailed(t *testing.T) {
	t.Run("error message with value", func(t *testing.T) {
		cause := errors.New("invalid format")
		err := &ErrVTEPValidationFailed{
			Field: "LocalIP",
			Value: "not-an-ip",
			Cause: cause,
		}

		expectedMsg := "VTEP validation failed for LocalIP=not-an-ip: invalid format"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("error message without value", func(t *testing.T) {
		cause := errors.New("required field missing")
		err := &ErrVTEPValidationFailed{
			Field: "UnderlayIface",
			Value: "",
			Cause: cause,
		}

		expectedMsg := "VTEP validation failed for UnderlayIface: required field missing"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrVTEPValidationFailed{
			Field: "MTU",
			Cause: cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrHealthCheckFailed(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrHealthCheckFailed{
			TunnelID:   "tunnel-1",
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			Cause:      cause,
		}

		expectedMsg := "health check failed for tunnel tunnel-1 (remote: 10.0.0.2): timeout"
		assert.Equal(t, expectedMsg, err.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrHealthCheckFailed{
			TunnelID:   "tunnel-1",
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			Cause:      cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
		assert.True(t, errors.Is(err, cause))
	})
}

func TestErrorIs(t *testing.T) {
	t.Run("sentinel errors are unique", func(t *testing.T) {
		assert.False(t, errors.Is(ErrVNIOutOfRange, ErrVNIInUse))
		assert.False(t, errors.Is(ErrTunnelNotFound, ErrTunnelExists))
		assert.False(t, errors.Is(ErrMTUTooSmall, ErrInvalidVXLANPort))
	})

	t.Run("wrapped errors can be matched", func(t *testing.T) {
		original := ErrTunnelNotFound
		wrapped := &ErrTunnelDeletionFailed{
			TunnelID: "tunnel-1",
			Cause:    original,
		}

		assert.True(t, errors.Is(wrapped, original))
	})
}

func TestErrorAs(t *testing.T) {
	t.Run("can extract tunnel creation error", func(t *testing.T) {
		err := &ErrTunnelCreationFailed{
			RemoteVTEP: netip.MustParseAddr("10.0.0.2"),
			VNI:        1000100,
			Cause:      errors.New("test"),
		}

		var target *ErrTunnelCreationFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, VNI(1000100), target.VNI)
	})

	t.Run("can extract OVS operation error", func(t *testing.T) {
		err := &ErrOVSOperationFailed{
			Operation: "add_port",
			Target:    "vxlan-1",
			Cause:     errors.New("test"),
		}

		var target *ErrOVSOperationFailed
		assert.True(t, errors.As(err, &target))
		assert.Equal(t, "add_port", target.Operation)
	})
}

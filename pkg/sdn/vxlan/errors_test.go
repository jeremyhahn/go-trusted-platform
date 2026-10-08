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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{name: "ErrVNIOutOfRange", err: ErrVNIOutOfRange, msg: "VNI must be between 1 and 16777215"},
		{name: "ErrVNIInUse", err: ErrVNIInUse, msg: "VNI already in use"},
		{name: "ErrVTEPNotConfigured", err: ErrVTEPNotConfigured, msg: "VTEP not configured"},
		{name: "ErrInvalidVTEPIP", err: ErrInvalidVTEPIP, msg: "invalid VTEP IP address"},
		{name: "ErrUnderlayNotReady", err: ErrUnderlayNotReady, msg: "underlay interface not ready"},
		{name: "ErrMTUTooSmall", err: ErrMTUTooSmall, msg: "underlay MTU too small for a 9000-byte overlay (minimum 9050)"},
		{name: "ErrInvalidVXLANPort", err: ErrInvalidVXLANPort, msg: "invalid VXLAN UDP port"},
		{name: "ErrVLANOutOfRange", err: ErrVLANOutOfRange, msg: "VLAN ID out of range (0-4094)"},
		{name: "ErrMappingNotFound", err: ErrMappingNotFound, msg: "VNI/VLAN mapping not found"},
		{name: "ErrManagerNotStarted", err: ErrManagerNotStarted, msg: "VTEP manager not started"},
		{name: "ErrManagerAlreadyStarted", err: ErrManagerAlreadyStarted, msg: "VTEP manager already started"},
		{name: "ErrInvalidPortName", err: ErrInvalidPortName, msg: "VXLAN port name is empty"},
		{name: "ErrOVSClientNil", err: ErrOVSClientNil, msg: "OVS client is nil"},
		{name: "ErrBridgeNameEmpty", err: ErrBridgeNameEmpty, msg: "bridge name is empty"},
		{name: "ErrLoggerNil", err: ErrLoggerNil, msg: "logger is nil"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, tc.err)
			assert.Equal(t, tc.msg, tc.err.Error())
		})
	}
}

func TestErrPortConflict(t *testing.T) {
	err := &ErrPortConflict{Port: "vxlan-evpn", Options: map[string]string{"remote_ip": "10.0.0.2"}}
	assert.Contains(t, err.Error(), "vxlan-evpn")
	assert.Contains(t, err.Error(), "remote_ip:10.0.0.2")

	var target *ErrPortConflict
	assert.True(t, errors.As(error(err), &target))
	assert.Equal(t, "vxlan-evpn", target.Port)
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

func TestErrorIs(t *testing.T) {
	t.Run("sentinel errors are unique", func(t *testing.T) {
		assert.False(t, errors.Is(ErrVNIOutOfRange, ErrVNIInUse))
		assert.False(t, errors.Is(ErrMTUTooSmall, ErrInvalidVXLANPort))
	})

	t.Run("wrapped errors can be matched", func(t *testing.T) {
		wrapped := &ErrOVSOperationFailed{Operation: "resolve ofport", Target: "vxlan-evpn", Cause: ErrManagerNotStarted}
		assert.True(t, errors.Is(wrapped, ErrManagerNotStarted))
	})
}

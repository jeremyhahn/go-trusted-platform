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

package pxe

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
		{"ErrInvalidConfig", ErrInvalidConfig, "invalid configuration"},
		{"ErrInvalidVLAN", ErrInvalidVLAN, "invalid VLAN ID"},
		{"ErrInvalidTimeout", ErrInvalidTimeout, "invalid timeout"},
		{"ErrInvalidFirmwareConfig", ErrInvalidFirmwareConfig, "invalid firmware configuration"},
		{"ErrFirmwareNotFound", ErrFirmwareNotFound, "firmware file not found"},
		{"ErrFirmwareDigestMismatch", ErrFirmwareDigestMismatch, "firmware digest mismatch"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.msg, tt.err.Error())
		})
	}
}

func TestErrServiceNotInitialized_Error(t *testing.T) {
	err := ErrServiceNotInitialized{}
	assert.Equal(t, "pxe: service not initialized", err.Error())
}

func TestErrServiceNotRunning_Error(t *testing.T) {
	err := ErrServiceNotRunning{}
	assert.Equal(t, "pxe: service is not running", err.Error())
}

func TestErrServiceAlreadyRunning_Error(t *testing.T) {
	err := ErrServiceAlreadyRunning{}
	assert.Equal(t, "pxe: service is already running", err.Error())
}

func TestErrInvalidConfiguration_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidConfiguration
		expected string
	}{
		{
			name:     "with_field_and_reason",
			err:      ErrInvalidConfiguration{Field: "timeout", Reason: "must be positive"},
			expected: "pxe: invalid configuration for timeout: must be positive",
		},
		{
			name:     "reason_only",
			err:      ErrInvalidConfiguration{Reason: "general error"},
			expected: "pxe: invalid configuration: general error",
		},
		{
			name:     "field_only",
			err:      ErrInvalidConfiguration{Field: "timeout"},
			expected: "pxe: invalid configuration for timeout: ",
		},
		{
			name:     "empty",
			err:      ErrInvalidConfiguration{},
			expected: "pxe: invalid configuration: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrDeviceNotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDeviceNotFound
		expected string
	}{
		{
			name:     "with_device_id",
			err:      ErrDeviceNotFound{DeviceID: "device-123"},
			expected: "pxe: device not found: device-123",
		},
		{
			name:     "with_mac_address",
			err:      ErrDeviceNotFound{MACAddress: "00:11:22:33:44:55"},
			expected: "pxe: device not found with MAC: 00:11:22:33:44:55",
		},
		{
			name:     "empty",
			err:      ErrDeviceNotFound{},
			expected: "pxe: device not found",
		},
		{
			name:     "device_id_takes_precedence",
			err:      ErrDeviceNotFound{DeviceID: "device-123", MACAddress: "00:11:22:33:44:55"},
			expected: "pxe: device not found: device-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrDeviceAlreadyExists_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrDeviceAlreadyExists
		expected string
	}{
		{
			name:     "with_device_id_only",
			err:      ErrDeviceAlreadyExists{DeviceID: "device-123"},
			expected: "pxe: device already exists: device-123",
		},
		{
			name:     "with_mac_address_only",
			err:      ErrDeviceAlreadyExists{MACAddress: "00:11:22:33:44:55"},
			expected: "pxe: device already exists (MAC=00:11:22:33:44:55)",
		},
		{
			name:     "with_both",
			err:      ErrDeviceAlreadyExists{DeviceID: "device-123", MACAddress: "00:11:22:33:44:55"},
			expected: "pxe: device already exists: device-123 (MAC=00:11:22:33:44:55)",
		},
		{
			name:     "empty",
			err:      ErrDeviceAlreadyExists{},
			expected: "pxe: device already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidMACAddress_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidMACAddress
		expected string
	}{
		{
			name:     "with_mac_and_reason",
			err:      ErrInvalidMACAddress{MACAddress: "invalid-mac", Reason: "wrong format"},
			expected: `pxe: invalid MAC address "invalid-mac": wrong format`,
		},
		{
			name:     "mac_only",
			err:      ErrInvalidMACAddress{MACAddress: "invalid-mac"},
			expected: `pxe: invalid MAC address "invalid-mac"`,
		},
		{
			name:     "reason_only",
			err:      ErrInvalidMACAddress{Reason: "empty"},
			expected: "pxe: invalid MAC address: empty",
		},
		{
			name:     "empty",
			err:      ErrInvalidMACAddress{},
			expected: "pxe: invalid MAC address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidState_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidState
		expected string
	}{
		{
			name:     "all_fields",
			err:      ErrInvalidState{DeviceID: "device-123", State: "invalid", Reason: "not recognized"},
			expected: `pxe: invalid state "invalid" for device "device-123": not recognized`,
		},
		{
			name:     "state_and_reason",
			err:      ErrInvalidState{State: "invalid", Reason: "not recognized"},
			expected: `pxe: invalid state "invalid": not recognized`,
		},
		{
			name:     "state_only",
			err:      ErrInvalidState{State: "invalid"},
			expected: `pxe: invalid state "invalid"`,
		},
		{
			name:     "device_and_reason",
			err:      ErrInvalidState{DeviceID: "device-123", Reason: "unexpected"},
			expected: `pxe: invalid state for device "device-123": unexpected`,
		},
		{
			name:     "empty",
			err:      ErrInvalidState{},
			expected: "pxe: invalid state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidStateTransition_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidStateTransition
		expected string
	}{
		{
			name: "all_fields",
			err: ErrInvalidStateTransition{
				DeviceID:  "device-123",
				FromState: "discovered",
				ToState:   "authorized",
				Reason:    "skip not allowed",
			},
			expected: `pxe: invalid state transition from "discovered" to "authorized" for device "device-123": skip not allowed`,
		},
		{
			name: "without_device",
			err: ErrInvalidStateTransition{
				FromState: "discovered",
				ToState:   "authorized",
				Reason:    "skip not allowed",
			},
			expected: `pxe: invalid state transition from "discovered" to "authorized": skip not allowed`,
		},
		{
			name: "without_reason",
			err: ErrInvalidStateTransition{
				DeviceID:  "device-123",
				FromState: "discovered",
				ToState:   "authorized",
			},
			expected: `pxe: invalid state transition from "discovered" to "authorized" for device "device-123"`,
		},
		{
			name: "minimal",
			err: ErrInvalidStateTransition{
				FromState: "a",
				ToState:   "b",
			},
			expected: `pxe: invalid state transition from "a" to "b"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrProvisioningFailed_Error(t *testing.T) {
	cause := errors.New("underlying error")

	tests := []struct {
		name     string
		err      ErrProvisioningFailed
		expected string
	}{
		{
			name:     "all_fields",
			err:      ErrProvisioningFailed{DeviceID: "device-123", Reason: "timeout", Cause: cause},
			expected: `pxe: provisioning failed for device "device-123": timeout: underlying error`,
		},
		{
			name:     "without_cause",
			err:      ErrProvisioningFailed{DeviceID: "device-123", Reason: "timeout"},
			expected: `pxe: provisioning failed for device "device-123": timeout`,
		},
		{
			name:     "without_device",
			err:      ErrProvisioningFailed{Reason: "timeout", Cause: cause},
			expected: "pxe: provisioning failed: timeout: underlying error",
		},
		{
			name:     "empty",
			err:      ErrProvisioningFailed{},
			expected: "pxe: provisioning failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrProvisioningFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrProvisioningFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))

	errNoCause := ErrProvisioningFailed{}
	assert.Nil(t, errNoCause.Unwrap())
}

func TestErrEnrollmentFailed_Error(t *testing.T) {
	cause := errors.New("certificate error")

	tests := []struct {
		name     string
		err      ErrEnrollmentFailed
		expected string
	}{
		{
			name:     "all_fields",
			err:      ErrEnrollmentFailed{DeviceID: "device-123", Reason: "cert invalid", Cause: cause},
			expected: `pxe: enrollment failed for device "device-123": cert invalid: certificate error`,
		},
		{
			name:     "without_cause",
			err:      ErrEnrollmentFailed{DeviceID: "device-123", Reason: "cert invalid"},
			expected: `pxe: enrollment failed for device "device-123": cert invalid`,
		},
		{
			name:     "empty",
			err:      ErrEnrollmentFailed{},
			expected: "pxe: enrollment failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrEnrollmentFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrEnrollmentFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrAuthorizationFailed_Error(t *testing.T) {
	cause := errors.New("auth error")

	tests := []struct {
		name     string
		err      ErrAuthorizationFailed
		expected string
	}{
		{
			name: "all_fields",
			err: ErrAuthorizationFailed{
				DeviceID:   "device-123",
				MACAddress: "00:11:22:33:44:55",
				Reason:     "policy violation",
				Cause:      cause,
			},
			expected: `pxe: authorization failed for device "device-123" (MAC=00:11:22:33:44:55): policy violation: auth error`,
		},
		{
			name: "without_mac",
			err: ErrAuthorizationFailed{
				DeviceID: "device-123",
				Reason:   "policy violation",
			},
			expected: `pxe: authorization failed for device "device-123": policy violation`,
		},
		{
			name:     "empty",
			err:      ErrAuthorizationFailed{},
			expected: "pxe: authorization failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrAuthorizationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrAuthorizationFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrVLANTransitionFailed_Error(t *testing.T) {
	cause := errors.New("ovs error")

	tests := []struct {
		name     string
		err      ErrVLANTransitionFailed
		expected string
	}{
		{
			name: "all_fields",
			err: ErrVLANTransitionFailed{
				DeviceID: "device-123",
				FromVLAN: 1,
				ToVLAN:   100,
				Reason:   "port not found",
				Cause:    cause,
			},
			expected: `pxe: VLAN transition failed for device "device-123" (from=1, to=100): port not found: ovs error`,
		},
		{
			name: "without_vlans",
			err: ErrVLANTransitionFailed{
				DeviceID: "device-123",
				Reason:   "port not found",
			},
			expected: `pxe: VLAN transition failed for device "device-123": port not found`,
		},
		{
			name: "vlans_only",
			err: ErrVLANTransitionFailed{
				FromVLAN: 1,
				ToVLAN:   100,
			},
			expected: "pxe: VLAN transition failed (from=1, to=100)",
		},
		{
			name:     "empty",
			err:      ErrVLANTransitionFailed{},
			expected: "pxe: VLAN transition failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrVLANTransitionFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrVLANTransitionFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrFirmwareVerificationFailed_Error(t *testing.T) {
	cause := errors.New("hash mismatch")

	tests := []struct {
		name     string
		err      ErrFirmwareVerificationFailed
		expected string
	}{
		{
			name: "all_fields",
			err: ErrFirmwareVerificationFailed{
				DeviceID:     "device-123",
				FirmwarePath: "/boot/ipxe.efi",
				Reason:       "digest mismatch",
				Cause:        cause,
			},
			expected: `pxe: firmware verification failed for device "device-123" (firmware="/boot/ipxe.efi"): digest mismatch: hash mismatch`,
		},
		{
			name: "without_device",
			err: ErrFirmwareVerificationFailed{
				FirmwarePath: "/boot/ipxe.efi",
				Reason:       "digest mismatch",
			},
			expected: `pxe: firmware verification failed (firmware="/boot/ipxe.efi"): digest mismatch`,
		},
		{
			name:     "empty",
			err:      ErrFirmwareVerificationFailed{},
			expected: "pxe: firmware verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrFirmwareVerificationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrFirmwareVerificationFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrISONotFound_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrISONotFound
		expected string
	}{
		{
			name:     "with_iso_id",
			err:      ErrISONotFound{ISOID: "iso-123"},
			expected: "pxe: ISO not found: iso-123",
		},
		{
			name:     "with_iso_name",
			err:      ErrISONotFound{ISOName: "ubuntu-22.04.iso"},
			expected: "pxe: ISO not found with name: ubuntu-22.04.iso",
		},
		{
			name:     "iso_id_takes_precedence",
			err:      ErrISONotFound{ISOID: "iso-123", ISOName: "ubuntu-22.04.iso"},
			expected: "pxe: ISO not found: iso-123",
		},
		{
			name:     "empty",
			err:      ErrISONotFound{},
			expected: "pxe: ISO not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrWebhookValidationFailed_Error(t *testing.T) {
	cause := errors.New("json parse error")

	tests := []struct {
		name     string
		err      ErrWebhookValidationFailed
		expected string
	}{
		{
			name: "all_fields",
			err: ErrWebhookValidationFailed{
				WebhookType: "install_complete",
				Field:       "mac_address",
				Reason:      "invalid format",
				Cause:       cause,
			},
			expected: `pxe: webhook validation failed for "install_complete" (field="mac_address"): invalid format: json parse error`,
		},
		{
			name: "without_field",
			err: ErrWebhookValidationFailed{
				WebhookType: "install_complete",
				Reason:      "invalid format",
			},
			expected: `pxe: webhook validation failed for "install_complete": invalid format`,
		},
		{
			name:     "empty",
			err:      ErrWebhookValidationFailed{},
			expected: "pxe: webhook validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrWebhookValidationFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrWebhookValidationFailed{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrMaxRetriesExceeded_Error(t *testing.T) {
	cause := errors.New("network timeout")

	tests := []struct {
		name     string
		err      ErrMaxRetriesExceeded
		expected string
	}{
		{
			name: "all_fields",
			err: ErrMaxRetriesExceeded{
				Operation:  "enrollment",
				MaxRetries: 3,
				Reason:     "network issues",
				Cause:      cause,
			},
			expected: `pxe: max retries exceeded for "enrollment" (max=3): network issues: network timeout`,
		},
		{
			name: "without_max",
			err: ErrMaxRetriesExceeded{
				Operation: "enrollment",
				Reason:    "network issues",
			},
			expected: `pxe: max retries exceeded for "enrollment": network issues`,
		},
		{
			name: "max_only",
			err: ErrMaxRetriesExceeded{
				MaxRetries: 5,
			},
			expected: "pxe: max retries exceeded (max=5)",
		},
		{
			name:     "empty",
			err:      ErrMaxRetriesExceeded{},
			expected: "pxe: max retries exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrMaxRetriesExceeded_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrMaxRetriesExceeded{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestErrTimeout_Error(t *testing.T) {
	cause := errors.New("context deadline exceeded")

	tests := []struct {
		name     string
		err      ErrTimeout
		expected string
	}{
		{
			name: "all_fields",
			err: ErrTimeout{
				Operation: "enrollment",
				Duration:  "5m",
				Cause:     cause,
			},
			expected: "pxe: enrollment timed out after 5m: context deadline exceeded",
		},
		{
			name: "without_duration",
			err: ErrTimeout{
				Operation: "enrollment",
			},
			expected: "pxe: enrollment timed out",
		},
		{
			name: "without_operation",
			err: ErrTimeout{
				Duration: "5m",
			},
			expected: "pxe: operation timed out after 5m",
		},
		{
			name:     "empty",
			err:      ErrTimeout{},
			expected: "pxe: operation timed out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrTimeout_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrTimeout{Cause: cause}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

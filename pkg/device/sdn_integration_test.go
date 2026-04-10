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

package device

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkEvent_String(t *testing.T) {
	tests := []struct {
		name     string
		event    NetworkEvent
		expected string
	}{
		{
			name:     "connect event",
			event:    NetworkEventConnect,
			expected: "connect",
		},
		{
			name:     "enrolled event",
			event:    NetworkEventEnrolled,
			expected: "enrolled",
		},
		{
			name:     "compliance fail event",
			event:    NetworkEventComplianceFail,
			expected: "compliance_fail",
		},
		{
			name:     "disconnect event",
			event:    NetworkEventDisconnect,
			expected: "disconnect",
		},
		{
			name:     "unknown event negative",
			event:    NetworkEvent(-1),
			expected: "unknown",
		},
		{
			name:     "unknown event out of range",
			event:    NetworkEvent(100),
			expected: "unknown",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.event.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNetworkEvent_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		event    NetworkEvent
		expected bool
	}{
		{
			name:     "connect is valid",
			event:    NetworkEventConnect,
			expected: true,
		},
		{
			name:     "enrolled is valid",
			event:    NetworkEventEnrolled,
			expected: true,
		},
		{
			name:     "compliance fail is valid",
			event:    NetworkEventComplianceFail,
			expected: true,
		},
		{
			name:     "disconnect is valid",
			event:    NetworkEventDisconnect,
			expected: true,
		},
		{
			name:     "negative value is invalid",
			event:    NetworkEvent(-1),
			expected: false,
		},
		{
			name:     "out of range value is invalid",
			event:    NetworkEvent(100),
			expected: false,
		},
		{
			name:     "boundary value plus one is invalid",
			event:    NetworkEvent(4),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.event.IsValid()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNetworkPhase_String(t *testing.T) {
	tests := []struct {
		name     string
		phase    NetworkPhase
		expected string
	}{
		{
			name:     "provisioning phase",
			phase:    NetworkPhaseProvisioning,
			expected: "provisioning",
		},
		{
			name:     "production phase",
			phase:    NetworkPhaseProduction,
			expected: "production",
		},
		{
			name:     "quarantine phase",
			phase:    NetworkPhaseQuarantine,
			expected: "quarantine",
		},
		{
			name:     "empty phase",
			phase:    NetworkPhase(""),
			expected: "",
		},
		{
			name:     "custom phase",
			phase:    NetworkPhase("custom"),
			expected: "custom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.phase.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNetworkPhase_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		phase    NetworkPhase
		expected bool
	}{
		{
			name:     "provisioning is valid",
			phase:    NetworkPhaseProvisioning,
			expected: true,
		},
		{
			name:     "production is valid",
			phase:    NetworkPhaseProduction,
			expected: true,
		},
		{
			name:     "quarantine is valid",
			phase:    NetworkPhaseQuarantine,
			expected: true,
		},
		{
			name:     "empty phase is invalid",
			phase:    NetworkPhase(""),
			expected: false,
		},
		{
			name:     "unknown phase is invalid",
			phase:    NetworkPhase("unknown"),
			expected: false,
		},
		{
			name:     "misspelled phase is invalid",
			phase:    NetworkPhase("provisionning"),
			expected: false,
		},
		{
			name:     "uppercase phase is invalid",
			phase:    NetworkPhase("PROVISIONING"),
			expected: false,
		},
		{
			name:     "mixed case phase is invalid",
			phase:    NetworkPhase("Provisioning"),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.phase.IsValid()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNetworkEventContext_Validate(t *testing.T) {
	validProfile := &entities.DeviceProfile{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "test-profile",
	}

	tests := []struct {
		name        string
		ctx         *NetworkEventContext
		expectedErr error
	}{
		{
			name: "valid context with all required fields",
			ctx: &NetworkEventContext{
				DeviceID: "device-001",
				PortID:   "port-001",
				MAC:      "00:11:22:33:44:55",
				Serial:   "SN123456",
				Profile:  validProfile,
				Phase:    NetworkPhaseProvisioning,
				Reason:   "initial connection",
			},
			expectedErr: nil,
		},
		{
			name: "valid context with minimal required fields",
			ctx: &NetworkEventContext{
				PortID:  "port-002",
				MAC:     "AA:BB:CC:DD:EE:FF",
				Profile: validProfile,
				Phase:   NetworkPhaseProduction,
			},
			expectedErr: nil,
		},
		{
			name: "valid context with quarantine phase",
			ctx: &NetworkEventContext{
				PortID:  "port-003",
				MAC:     "11:22:33:44:55:66",
				Profile: validProfile,
				Phase:   NetworkPhaseQuarantine,
			},
			expectedErr: nil,
		},
		{
			name: "missing port ID returns error",
			ctx: &NetworkEventContext{
				PortID:  "",
				MAC:     "00:11:22:33:44:55",
				Profile: validProfile,
				Phase:   NetworkPhaseProvisioning,
			},
			expectedErr: ErrPortIDEmpty,
		},
		{
			name: "missing MAC returns error",
			ctx: &NetworkEventContext{
				PortID:  "port-001",
				MAC:     "",
				Profile: validProfile,
				Phase:   NetworkPhaseProvisioning,
			},
			expectedErr: ErrMACEmpty,
		},
		{
			name: "nil profile returns error",
			ctx: &NetworkEventContext{
				PortID:  "port-001",
				MAC:     "00:11:22:33:44:55",
				Profile: nil,
				Phase:   NetworkPhaseProvisioning,
			},
			expectedErr: ErrProfileNil,
		},
		{
			name: "invalid phase returns error",
			ctx: &NetworkEventContext{
				PortID:  "port-001",
				MAC:     "00:11:22:33:44:55",
				Profile: validProfile,
				Phase:   NetworkPhase("invalid"),
			},
			expectedErr: ErrInvalidNetworkPhase,
		},
		{
			name: "empty phase returns error",
			ctx: &NetworkEventContext{
				PortID:  "port-001",
				MAC:     "00:11:22:33:44:55",
				Profile: validProfile,
				Phase:   NetworkPhase(""),
			},
			expectedErr: ErrInvalidNetworkPhase,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ctx.Validate()
			if tc.expectedErr != nil {
				require.Error(t, err)
				assert.Equal(t, tc.expectedErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNetworkEventContext_Validate_ErrorPriority(t *testing.T) {
	// Test that validation errors are returned in the correct priority order
	// PortID -> MAC -> Profile -> Phase

	t.Run("port ID checked before MAC", func(t *testing.T) {
		ctx := &NetworkEventContext{
			PortID:  "",
			MAC:     "",
			Profile: nil,
			Phase:   NetworkPhase("invalid"),
		}
		err := ctx.Validate()
		require.Error(t, err)
		assert.Equal(t, ErrPortIDEmpty, err)
	})

	t.Run("MAC checked before profile", func(t *testing.T) {
		ctx := &NetworkEventContext{
			PortID:  "port-001",
			MAC:     "",
			Profile: nil,
			Phase:   NetworkPhase("invalid"),
		}
		err := ctx.Validate()
		require.Error(t, err)
		assert.Equal(t, ErrMACEmpty, err)
	})

	t.Run("profile checked before phase", func(t *testing.T) {
		ctx := &NetworkEventContext{
			PortID:  "port-001",
			MAC:     "00:11:22:33:44:55",
			Profile: nil,
			Phase:   NetworkPhase("invalid"),
		}
		err := ctx.Validate()
		require.Error(t, err)
		assert.Equal(t, ErrProfileNil, err)
	})

	t.Run("phase checked last", func(t *testing.T) {
		ctx := &NetworkEventContext{
			PortID:  "port-001",
			MAC:     "00:11:22:33:44:55",
			Profile: &entities.DeviceProfile{ID: 1},
			Phase:   NetworkPhase("invalid"),
		}
		err := ctx.Validate()
		require.Error(t, err)
		assert.Equal(t, ErrInvalidNetworkPhase, err)
	})
}

func TestNetworkEventContext_Validate_WithMetadata(t *testing.T) {
	validProfile := &entities.DeviceProfile{
		ID:       1,
		TenantID: "tenant-1",
		Name:     "test-profile",
	}

	t.Run("context with metadata validates successfully", func(t *testing.T) {
		ctx := &NetworkEventContext{
			DeviceID: "device-001",
			PortID:   "port-001",
			MAC:      "00:11:22:33:44:55",
			Serial:   "SN123456",
			Profile:  validProfile,
			Phase:    NetworkPhaseProvisioning,
			Reason:   "compliance check failed",
			Metadata: map[string]string{
				"switch_id":      "switch-001",
				"location":       "rack-42",
				"compliance_ref": "CR-2025-001",
			},
		}
		err := ctx.Validate()
		require.NoError(t, err)
	})

	t.Run("context with empty metadata validates successfully", func(t *testing.T) {
		ctx := &NetworkEventContext{
			PortID:   "port-001",
			MAC:      "00:11:22:33:44:55",
			Profile:  validProfile,
			Phase:    NetworkPhaseProduction,
			Metadata: map[string]string{},
		}
		err := ctx.Validate()
		require.NoError(t, err)
	})

	t.Run("context with nil metadata validates successfully", func(t *testing.T) {
		ctx := &NetworkEventContext{
			PortID:   "port-001",
			MAC:      "00:11:22:33:44:55",
			Profile:  validProfile,
			Phase:    NetworkPhaseQuarantine,
			Metadata: nil,
		}
		err := ctx.Validate()
		require.NoError(t, err)
	})
}

func TestTypedErrors(t *testing.T) {
	// Verify that all typed errors are properly defined and unique
	t.Run("error messages are not empty", func(t *testing.T) {
		assert.NotEmpty(t, ErrSDNIntegrationNil.Error())
		assert.NotEmpty(t, ErrInvalidNetworkEvent.Error())
		assert.NotEmpty(t, ErrInvalidNetworkPhase.Error())
		assert.NotEmpty(t, ErrNetworkPhaseNotConfigured.Error())
		assert.NotEmpty(t, ErrProfileNil.Error())
		assert.NotEmpty(t, ErrPortIDEmpty.Error())
		assert.NotEmpty(t, ErrMACEmpty.Error())
	})

	t.Run("error messages are unique", func(t *testing.T) {
		errors := []error{
			ErrSDNIntegrationNil,
			ErrInvalidNetworkEvent,
			ErrInvalidNetworkPhase,
			ErrNetworkPhaseNotConfigured,
			ErrProfileNil,
			ErrPortIDEmpty,
			ErrMACEmpty,
		}

		seen := make(map[string]bool)
		for _, err := range errors {
			msg := err.Error()
			assert.False(t, seen[msg], "duplicate error message: %s", msg)
			seen[msg] = true
		}
	})
}

func TestNetworkEvent_Constants(t *testing.T) {
	// Verify that network event constants have expected iota values
	t.Run("network event iota values", func(t *testing.T) {
		assert.Equal(t, NetworkEvent(0), NetworkEventConnect)
		assert.Equal(t, NetworkEvent(1), NetworkEventEnrolled)
		assert.Equal(t, NetworkEvent(2), NetworkEventComplianceFail)
		assert.Equal(t, NetworkEvent(3), NetworkEventDisconnect)
	})
}

func TestNetworkPhase_Constants(t *testing.T) {
	// Verify that network phase constants have expected string values
	t.Run("network phase string values", func(t *testing.T) {
		assert.Equal(t, "provisioning", string(NetworkPhaseProvisioning))
		assert.Equal(t, "production", string(NetworkPhaseProduction))
		assert.Equal(t, "quarantine", string(NetworkPhaseQuarantine))
	})
}

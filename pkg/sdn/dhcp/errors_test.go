// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrLeaseConflict(t *testing.T) {
	t.Run("Error message format", func(t *testing.T) {
		ip := netip.MustParseAddr("192.168.1.100")
		existingMAC, _ := net.ParseMAC("00:11:22:33:44:55")
		requestedMAC, _ := net.ParseMAC("66:77:88:99:AA:BB")

		err := &ErrLeaseConflict{
			IP:           ip,
			ExistingMAC:  existingMAC,
			RequestedMAC: requestedMAC,
		}

		msg := err.Error()
		assert.Contains(t, msg, "192.168.1.100")
		assert.Contains(t, msg, "00:11:22:33:44:55")
		assert.Contains(t, msg, "66:77:88:99:aa:bb")
		assert.Contains(t, msg, "lease conflict")
	})
}

func TestErrPoolExhausted(t *testing.T) {
	t.Run("Error message format", func(t *testing.T) {
		err := &ErrPoolExhausted{
			PoolID: "test-pool-123",
		}

		msg := err.Error()
		assert.Contains(t, msg, "test-pool-123")
		assert.Contains(t, msg, "exhausted")
	})
}

func TestErrDHCPOperation(t *testing.T) {
	t.Run("Error with cause", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		cause := errors.New("allocation failed")

		err := &ErrDHCPOperation{
			Operation: "discover",
			MAC:       mac,
			Cause:     cause,
		}

		msg := err.Error()
		assert.Contains(t, msg, "DHCP")
		assert.Contains(t, msg, "discover")
		assert.Contains(t, msg, "00:11:22:33:44:55")
		assert.Contains(t, msg, "allocation failed")

		// Test Unwrap
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Error without cause", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		err := &ErrDHCPOperation{
			Operation: "request",
			MAC:       mac,
		}

		msg := err.Error()
		assert.Contains(t, msg, "DHCP")
		assert.Contains(t, msg, "request")
		assert.Contains(t, msg, "00:11:22:33:44:55")
		assert.NotContains(t, msg, "nil")

		assert.Nil(t, err.Unwrap())
	})
}

func TestErrPXEOperation(t *testing.T) {
	t.Run("Error with cause", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		cause := errors.New("boot file not found")

		err := &ErrPXEOperation{
			Operation: "boot",
			MAC:       mac,
			Cause:     cause,
		}

		msg := err.Error()
		assert.Contains(t, msg, "PXE")
		assert.Contains(t, msg, "boot")
		assert.Contains(t, msg, "00:11:22:33:44:55")
		assert.Contains(t, msg, "boot file not found")

		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Error without cause", func(t *testing.T) {
		mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")

		err := &ErrPXEOperation{
			Operation: "tftp",
			MAC:       mac,
		}

		msg := err.Error()
		assert.Contains(t, msg, "PXE")
		assert.Contains(t, msg, "tftp")
		assert.Contains(t, msg, "aa:bb:cc:dd:ee:ff")

		assert.Nil(t, err.Unwrap())
	})
}

func TestErrInterfaceOperation(t *testing.T) {
	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("permission denied")

		err := &ErrInterfaceOperation{
			Interface: "eth0",
			Operation: "bind",
			Cause:     cause,
		}

		msg := err.Error()
		assert.Contains(t, msg, "eth0")
		assert.Contains(t, msg, "bind")
		assert.Contains(t, msg, "permission denied")

		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Error without cause", func(t *testing.T) {
		err := &ErrInterfaceOperation{
			Interface: "br0",
			Operation: "start",
		}

		msg := err.Error()
		assert.Contains(t, msg, "br0")
		assert.Contains(t, msg, "start")

		assert.Nil(t, err.Unwrap())
	})
}

func TestErrServerOperation(t *testing.T) {
	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("socket in use")

		err := &ErrServerOperation{
			Operation: "startup",
			Cause:     cause,
		}

		msg := err.Error()
		assert.Contains(t, msg, "server")
		assert.Contains(t, msg, "startup")
		assert.Contains(t, msg, "socket in use")

		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Error without cause", func(t *testing.T) {
		err := &ErrServerOperation{
			Operation: "shutdown",
		}

		msg := err.Error()
		assert.Contains(t, msg, "server")
		assert.Contains(t, msg, "shutdown")

		assert.Nil(t, err.Unwrap())
	})
}

func TestIsLeaseError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrLeaseNotFound",
			err:      ErrLeaseNotFound,
			expected: true,
		},
		{
			name:     "ErrLeaseExpired",
			err:      ErrLeaseExpired,
			expected: true,
		},
		{
			name: "ErrLeaseConflict",
			err: &ErrLeaseConflict{
				IP:           netip.MustParseAddr("192.168.1.1"),
				ExistingMAC:  net.HardwareAddr{0, 1, 2, 3, 4, 5},
				RequestedMAC: net.HardwareAddr{5, 4, 3, 2, 1, 0},
			},
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      ErrInvalidMAC,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsLeaseError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrInvalidMAC",
			err:      ErrInvalidMAC,
			expected: true,
		},
		{
			name:     "ErrInvalidIP",
			err:      ErrInvalidIP,
			expected: true,
		},
		{
			name:     "ErrNilRequest",
			err:      ErrNilRequest,
			expected: true,
		},
		{
			name:     "ErrNilResponse",
			err:      ErrNilResponse,
			expected: true,
		},
		{
			name:     "ErrInvalidMessageType",
			err:      ErrInvalidMessageType,
			expected: true,
		},
		{
			name:     "ErrInvalidBootFile",
			err:      ErrInvalidBootFile,
			expected: true,
		},
		{
			name:     "ErrInvalidNextServer",
			err:      ErrInvalidNextServer,
			expected: true,
		},
		{
			name:     "ErrNilConfig",
			err:      ErrNilConfig,
			expected: true,
		},
		{
			name:     "ErrInvalidConfig",
			err:      ErrInvalidConfig,
			expected: true,
		},
		{
			name:     "ErrInvalidInterface",
			err:      ErrInvalidInterface,
			expected: true,
		},
		{
			name:     "ErrInvalidLeaseRequest",
			err:      ErrInvalidLeaseRequest,
			expected: true,
		},
		{
			name:     "ErrIPAMBackendInvalid",
			err:      ErrIPAMBackendInvalid,
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      ErrLeaseNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidationError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsServerError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrServerAlreadyRunning",
			err:      ErrServerAlreadyRunning,
			expected: true,
		},
		{
			name:     "ErrServerNotRunning",
			err:      ErrServerNotRunning,
			expected: true,
		},
		{
			name:     "ErrNoInterfacesConfigured",
			err:      ErrNoInterfacesConfigured,
			expected: true,
		},
		{
			name:     "ErrInterfaceNotFound",
			err:      ErrInterfaceNotFound,
			expected: true,
		},
		{
			name:     "ErrBindFailed",
			err:      ErrBindFailed,
			expected: true,
		},
		{
			name: "ErrServerOperation",
			err: &ErrServerOperation{
				Operation: "test",
			},
			expected: true,
		},
		{
			name: "ErrInterfaceOperation",
			err: &ErrInterfaceOperation{
				Interface: "eth0",
				Operation: "bind",
			},
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      ErrLeaseNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsServerError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsPoolError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ErrPoolNotFound",
			err:      ErrPoolNotFound,
			expected: true,
		},
		{
			name:     "ErrPoolIDRequired",
			err:      ErrPoolIDRequired,
			expected: true,
		},
		{
			name: "ErrPoolExhausted",
			err: &ErrPoolExhausted{
				PoolID: "test",
			},
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      ErrLeaseNotFound,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPoolError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	sentinelErrors := []struct {
		name string
		err  error
	}{
		{"ErrPluginClosed", ErrPluginClosed},
		{"ErrAllocatorRequired", ErrAllocatorRequired},
		{"ErrPoolIDRequired", ErrPoolIDRequired},
		{"ErrPoolNotFound", ErrPoolNotFound},
		{"ErrLeaseNotFound", ErrLeaseNotFound},
		{"ErrInvalidMAC", ErrInvalidMAC},
		{"ErrInvalidIP", ErrInvalidIP},
		{"ErrLeaseExpired", ErrLeaseExpired},
		{"ErrNilRequest", ErrNilRequest},
		{"ErrNilResponse", ErrNilResponse},
		{"ErrAllocationFailed", ErrAllocationFailed},
		{"ErrInvalidMessageType", ErrInvalidMessageType},
		{"ErrPXENotSupported", ErrPXENotSupported},
		{"ErrInvalidBootFile", ErrInvalidBootFile},
		{"ErrInvalidNextServer", ErrInvalidNextServer},
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrInvalidLeaseRequest", ErrInvalidLeaseRequest},
		{"ErrIPAMBackendInvalid", ErrIPAMBackendInvalid},
		{"ErrServerAlreadyRunning", ErrServerAlreadyRunning},
		{"ErrServerNotRunning", ErrServerNotRunning},
		{"ErrNoInterfacesConfigured", ErrNoInterfacesConfigured},
		{"ErrInvalidInterface", ErrInvalidInterface},
		{"ErrInterfaceNotFound", ErrInterfaceNotFound},
		{"ErrBindFailed", ErrBindFailed},
		{"ErrNilConfig", ErrNilConfig},
		{"ErrNilLeaseManager", ErrNilLeaseManager},
		{"ErrNilIPAMAllocator", ErrNilIPAMAllocator},
	}

	for _, se := range sentinelErrors {
		t.Run(se.name, func(t *testing.T) {
			require.NotNil(t, se.err)
			assert.NotEmpty(t, se.err.Error())
		})
	}
}

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

package netlink

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetLinkUp_ErrorConditions tests all error conditions in SetLinkUp
func TestSetLinkUp_ErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		errType ErrorType
	}{
		{
			name:    "empty interface name",
			ifName:  "",
			errType: ErrorTypeInvalidName,
		},
		{
			name:    "nonexistent interface",
			ifName:  "nonexist-if-xyz-123",
			errType: ErrorTypeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.SetLinkUp(tt.ifName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestSetLinkDown_ErrorConditions tests all error conditions in SetLinkDown
func TestSetLinkDown_ErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		errType ErrorType
	}{
		{
			name:    "empty interface name",
			ifName:  "",
			errType: ErrorTypeInvalidName,
		},
		{
			name:    "nonexistent interface",
			ifName:  "nonexist-if-xyz-456",
			errType: ErrorTypeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.SetLinkDown(tt.ifName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestSetLinkMTU_AllErrorConditions tests all error paths in SetLinkMTU
func TestSetLinkMTU_AllErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		mtu     int
		errType ErrorType
	}{
		{
			name:    "empty interface name",
			ifName:  "",
			mtu:     1500,
			errType: ErrorTypeInvalidName,
		},
		{
			name:    "MTU too small",
			ifName:  "lo",
			mtu:     67,
			errType: ErrorTypeSetupFailed,
		},
		{
			name:    "MTU too large",
			ifName:  "lo",
			mtu:     65537,
			errType: ErrorTypeSetupFailed,
		},
		{
			name:    "negative MTU",
			ifName:  "lo",
			mtu:     -100,
			errType: ErrorTypeSetupFailed,
		},
		{
			name:    "nonexistent interface with valid MTU",
			ifName:  "nonexist-if-mtu-789",
			mtu:     1500,
			errType: ErrorTypeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.SetLinkMTU(tt.ifName, tt.mtu)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestDeleteLink_AllErrorConditions tests all error paths in DeleteLink
func TestDeleteLink_AllErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		errType ErrorType
	}{
		{
			name:    "empty interface name",
			ifName:  "",
			errType: ErrorTypeInvalidName,
		},
		{
			name:    "nonexistent interface",
			ifName:  "nonexist-del-if-321",
			errType: ErrorTypeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.DeleteLink(tt.ifName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestGetLink_AllErrorConditions tests all error paths in GetLink
func TestGetLink_AllErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		errType ErrorType
	}{
		{
			name:    "empty interface name",
			ifName:  "",
			errType: ErrorTypeInvalidName,
		},
		{
			name:    "nonexistent interface",
			ifName:  "nonexist-get-if-654",
			errType: ErrorTypeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.GetLink(tt.ifName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestGetTAP_AllErrorConditions tests all error paths in GetTAP
func TestGetTAP_AllErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		errType ErrorType
		errMsg  string
	}{
		{
			name:    "empty interface name",
			ifName:  "",
			errType: ErrorTypeInvalidName,
			errMsg:  "invalid",
		},
		{
			name:    "nonexistent interface",
			ifName:  "tap-nonexist-987",
			errType: ErrorTypeNotFound,
			errMsg:  "not found",
		},
		{
			name:    "not a TAP device - loopback",
			ifName:  "lo",
			errType: ErrorTypeSetupFailed,
			errMsg:  "not a TAP device",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.GetTAP(tt.ifName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
			if tt.errMsg != "" {
				assert.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}

// TestListTAPs_EmptyResult tests ListTAPs when no TAP devices exist
func TestListTAPs_EmptyResult(t *testing.T) {
	m := NewManager()

	// Should succeed even if no TAP devices
	taps, err := m.ListTAPs()
	require.NoError(t, err)
	require.NotNil(t, taps)
	// May be empty or not depending on system state
	assert.GreaterOrEqual(t, len(taps), 0)
}

// TestListLinks_Success tests ListLinks success path
func TestListLinks_Success(t *testing.T) {
	m := NewManager()

	links, err := m.ListLinks()
	require.NoError(t, err)
	require.NotNil(t, links)
	assert.Greater(t, len(links), 0, "Should have at least loopback")

	// Verify each link has valid fields
	for _, link := range links {
		assert.Greater(t, link.Index, 0, "Index should be positive")
		assert.NotEmpty(t, link.Name, "Name should not be empty")
		assert.NotEmpty(t, link.Type, "Type should not be empty")
	}
}

// TestCreateTAP_InvalidConfig_AllCases tests all validation failures
func TestCreateTAP_InvalidConfig_AllCases(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		config  *TAPConfig
		errType ErrorType
		errMsg  string
	}{
		{
			name: "empty name",
			config: &TAPConfig{
				Name: "",
			},
			errType: ErrorTypeInvalidName,
			errMsg:  "empty name",
		},
		{
			name: "name too long - 16 chars",
			config: &TAPConfig{
				Name: "1234567890123456",
			},
			errType: ErrorTypeInvalidName,
			errMsg:  "too long",
		},
		{
			name: "name too long - 20 chars",
			config: &TAPConfig{
				Name: "12345678901234567890",
			},
			errType: ErrorTypeInvalidName,
			errMsg:  "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.CreateTAP(tt.config)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			if ne, ok := err.(*NetlinkError); ok {
				netlinkErr = ne
			}
			require.NotNil(t, netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
			if tt.errMsg != "" {
				assert.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}

// TestTAPConfig_Validate_BoundaryConditions tests validation boundary conditions
func TestTAPConfig_Validate_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name    string
		config  *TAPConfig
		wantErr bool
	}{
		{
			name: "single char name",
			config: &TAPConfig{
				Name: "a",
			},
			wantErr: false,
		},
		{
			name: "two char name",
			config: &TAPConfig{
				Name: "ab",
			},
			wantErr: false,
		},
		{
			name: "14 char name",
			config: &TAPConfig{
				Name: "12345678901234",
			},
			wantErr: false,
		},
		{
			name: "exactly 15 char name - max valid",
			config: &TAPConfig{
				Name: "123456789012345",
			},
			wantErr: false,
		},
		{
			name: "exactly 16 char name - min invalid",
			config: &TAPConfig{
				Name: "1234567890123456",
			},
			wantErr: true,
		},
		{
			name: "17 char name",
			config: &TAPConfig{
				Name: "12345678901234567",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestNetlinkError_Methods tests NetlinkError methods
func TestNetlinkError_Methods(t *testing.T) {
	t.Run("Error with cause", func(t *testing.T) {
		cause := assert.AnError
		err := &NetlinkError{
			Type:    ErrorTypeSetupFailed,
			Message: "test message",
			Cause:   cause,
		}

		errStr := err.Error()
		assert.Contains(t, errStr, "setup_failed")
		assert.Contains(t, errStr, "test message")
		assert.Contains(t, errStr, cause.Error())
	})

	t.Run("Error without cause", func(t *testing.T) {
		err := &NetlinkError{
			Type:    ErrorTypeNotFound,
			Message: "interface not found",
			Cause:   nil,
		}

		errStr := err.Error()
		assert.Contains(t, errStr, "not_found")
		assert.Contains(t, errStr, "interface not found")
		assert.NotContains(t, errStr, "assert.AnError")
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := assert.AnError
		err := &NetlinkError{
			Type:    ErrorTypePermission,
			Message: "permission denied",
			Cause:   cause,
		}

		unwrapped := err.Unwrap()
		assert.Equal(t, cause, unwrapped)
	})

	t.Run("Unwrap nil cause", func(t *testing.T) {
		err := &NetlinkError{
			Type:    ErrorTypeInvalidName,
			Message: "invalid name",
			Cause:   nil,
		}

		unwrapped := err.Unwrap()
		assert.Nil(t, unwrapped)
	})
}

// TestFlagHelpers_Comprehensive tests all flag helper functions comprehensively
func TestFlagHelpers_Comprehensive(t *testing.T) {
	t.Run("IsFlagSet - all combinations", func(t *testing.T) {
		// Test various flag combinations
		assert.True(t, IsFlagSet(0x1, 0x1))
		assert.True(t, IsFlagSet(0x3, 0x1))
		assert.True(t, IsFlagSet(0x3, 0x2))
		assert.False(t, IsFlagSet(0x1, 0x2))
		assert.False(t, IsFlagSet(0x0, 0x1))
	})

	t.Run("IsUp - comprehensive", func(t *testing.T) {
		assert.True(t, IsUp(0x1))
		assert.True(t, IsUp(0x1003))
		assert.False(t, IsUp(0x0))
		assert.False(t, IsUp(0x1000))
	})

	t.Run("IsRunning - comprehensive", func(t *testing.T) {
		assert.True(t, IsRunning(uint32(net.FlagRunning)))
		assert.True(t, IsRunning(0x1000|uint32(net.FlagRunning)))
		assert.False(t, IsRunning(0x0))
		assert.False(t, IsRunning(0x3))
	})
}

// TestLinkInfo_AllFields tests LinkInfo structure
func TestLinkInfo_StructFields(t *testing.T) {
	info := &LinkInfo{
		Index:        1,
		Name:         "test0",
		Type:         "dummy",
		Flags:        0x1003,
		MTU:          1500,
		HardwareAddr: "00:11:22:33:44:55",
		OperState:    LinkStateUp,
		Master:       0,
	}

	assert.Equal(t, 1, info.Index)
	assert.Equal(t, "test0", info.Name)
	assert.Equal(t, "dummy", info.Type)
	assert.Equal(t, uint32(0x1003), info.Flags)
	assert.Equal(t, 1500, info.MTU)
	assert.Equal(t, "00:11:22:33:44:55", info.HardwareAddr)
	assert.Equal(t, LinkStateUp, info.OperState)
	assert.Equal(t, 0, info.Master)
}

// TestTAPInfo_AllFields tests TAPInfo structure
func TestTAPInfo_StructFields(t *testing.T) {
	tapInfo := &TAPInfo{
		LinkInfo: LinkInfo{
			Index:        1,
			Name:         "tap0",
			Type:         "tuntap",
			Flags:        0x1003,
			MTU:          1500,
			HardwareAddr: "00:11:22:33:44:55",
			OperState:    LinkStateUp,
			Master:       0,
		},
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    true,
	}

	// Test embedded fields
	assert.Equal(t, 1, tapInfo.Index)
	assert.Equal(t, "tap0", tapInfo.Name)
	assert.Equal(t, "tuntap", tapInfo.Type)
	assert.Equal(t, uint32(0x1003), tapInfo.Flags)
	assert.Equal(t, 1500, tapInfo.MTU)
	assert.Equal(t, "00:11:22:33:44:55", tapInfo.HardwareAddr)
	assert.Equal(t, LinkStateUp, tapInfo.OperState)
	assert.Equal(t, 0, tapInfo.Master)

	// Test TAP-specific fields
	assert.Equal(t, uint32(1000), tapInfo.Owner)
	assert.Equal(t, uint32(1000), tapInfo.Group)
	assert.True(t, tapInfo.MultiQueue)
	assert.True(t, tapInfo.Persist)
}

// TestErrorConstructors_AllTypes tests all error constructor functions
func TestErrorConstructors_AllTypes(t *testing.T) {
	t.Run("ErrInvalidName", func(t *testing.T) {
		err := ErrInvalidName("test")
		assert.Contains(t, err.Error(), "invalid")
		assert.Contains(t, err.Error(), "test")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeInvalidName, netlinkErr.Type)
	})

	t.Run("ErrNotFound", func(t *testing.T) {
		err := ErrNotFound("iface0")
		assert.Contains(t, err.Error(), "not found")
		assert.Contains(t, err.Error(), "iface0")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
	})

	t.Run("ErrAlreadyExists", func(t *testing.T) {
		err := ErrAlreadyExists("tap1")
		assert.Contains(t, err.Error(), "already exists")
		assert.Contains(t, err.Error(), "tap1")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeAlreadyExists, netlinkErr.Type)
	})

	t.Run("ErrCreateFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrCreateFailed("br0", cause)
		assert.Contains(t, err.Error(), "create")
		assert.Contains(t, err.Error(), "br0")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeCreateFailed, netlinkErr.Type)
		assert.Equal(t, cause, netlinkErr.Cause)
	})

	t.Run("ErrDeleteFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrDeleteFailed("veth0", cause)
		assert.Contains(t, err.Error(), "delete")
		assert.Contains(t, err.Error(), "veth0")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeDeleteFailed, netlinkErr.Type)
		assert.Equal(t, cause, netlinkErr.Cause)
	})

	t.Run("ErrSetupFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrSetupFailed("tun0", "set MTU", cause)
		assert.Contains(t, err.Error(), "setup")
		assert.Contains(t, err.Error(), "tun0")
		assert.Contains(t, err.Error(), "set MTU")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
		assert.Equal(t, cause, netlinkErr.Cause)
	})

	t.Run("ErrStateFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrStateFailed("eth0", "up", cause)
		assert.Contains(t, err.Error(), "state")
		assert.Contains(t, err.Error(), "eth0")
		assert.Contains(t, err.Error(), "up")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypeStateFailed, netlinkErr.Type)
		assert.Equal(t, cause, netlinkErr.Cause)
	})

	t.Run("ErrPermission", func(t *testing.T) {
		cause := assert.AnError
		err := ErrPermission("create interface", cause)
		assert.Contains(t, err.Error(), "permission")
		assert.Contains(t, err.Error(), "create interface")
		assert.Contains(t, err.Error(), "CAP_NET_ADMIN")

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		require.NotNil(t, netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
		assert.Equal(t, cause, netlinkErr.Cause)
	})
}

// TestLinkState_Constants tests LinkState constant values
func TestLinkState_Constants(t *testing.T) {
	assert.Equal(t, LinkState("up"), LinkStateUp)
	assert.Equal(t, LinkState("down"), LinkStateDown)
	assert.Equal(t, LinkState("unknown"), LinkStateUnknown)
}

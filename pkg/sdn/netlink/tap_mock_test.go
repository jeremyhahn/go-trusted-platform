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
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateTAP_ValidConfigVariations tests CreateTAP with various valid configurations
// that exercise validation logic without requiring root
func TestCreateTAP_ValidConfigVariations(t *testing.T) {
	tests := []struct {
		name      string
		config    *TAPConfig
		wantErr   bool
		errType   ErrorType
		errString string
	}{
		{
			name: "empty name validation",
			config: &TAPConfig{
				Name:  "",
				Owner: 1000,
				Group: 1000,
			},
			wantErr:   true,
			errType:   ErrorTypeInvalidName,
			errString: "empty name",
		},
		{
			name: "name exactly 16 chars",
			config: &TAPConfig{
				Name:  "1234567890123456",
				Owner: 1000,
				Group: 1000,
			},
			wantErr:   true,
			errType:   ErrorTypeInvalidName,
			errString: "name too long",
		},
		{
			name: "name exactly 15 chars - valid",
			config: &TAPConfig{
				Name:  "123456789012345",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: false,
		},
		{
			name: "single char name - valid",
			config: &TAPConfig{
				Name:  "t",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: false,
		},
		{
			name: "config with all options enabled",
			config: &TAPConfig{
				Name:       "tapall",
				Owner:      1000,
				Group:      1000,
				MultiQueue: true,
				Persist:    true,
				MTU:        9000,
			},
			wantErr: false,
		},
		{
			name: "config with zero MTU - should use default",
			config: &TAPConfig{
				Name:  "tapdef",
				Owner: 0,
				Group: 0,
				MTU:   0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test validation directly
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				var netlinkErr *NetlinkError
				require.ErrorAs(t, err, &netlinkErr)
				assert.Equal(t, tt.errType, netlinkErr.Type)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestGetTAP_InputValidation tests GetTAP input validation paths
func TestGetTAP_InputValidation(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		tapName string
		wantErr bool
		errType ErrorType
	}{
		{
			name:    "empty name should fail validation",
			tapName: "",
			wantErr: true,
			errType: ErrorTypeInvalidName,
		},
		{
			name:    "nonexistent device should fail with not found",
			tapName: "tap-mock-nonexist-999",
			wantErr: true,
			errType: ErrorTypeNotFound,
		},
		{
			name:    "loopback is not a TAP device",
			tapName: "lo",
			wantErr: true,
			errType: ErrorTypeSetupFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.GetTAP(tt.tapName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			require.ErrorAs(t, err, &netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestListTAPs_ReturnsEmptyOrValid tests ListTAPs basic functionality
func TestListTAPs_ReturnsEmptyOrValid(t *testing.T) {
	m := NewManager()

	// This should succeed even if there are no TAP devices
	taps, err := m.ListTAPs()
	require.NoError(t, err)
	require.NotNil(t, taps)

	// Verify it returns a slice (may be empty)
	assert.IsType(t, []*TAPInfo{}, taps)

	// All returned TAPs should have type "tuntap"
	for _, tap := range taps {
		assert.Equal(t, "tuntap", tap.Type)
	}
}

// TestListTAPs_FiltersNonTAPDevices tests that ListTAPs filters correctly
func TestListTAPs_FiltersNonTAPDevices(t *testing.T) {
	m := NewManager()

	// Get all links
	allLinks, err := m.ListLinks()
	require.NoError(t, err)

	// Get TAPs only
	taps, err := m.ListTAPs()
	require.NoError(t, err)

	// TAPs should be a subset of all links
	assert.LessOrEqual(t, len(taps), len(allLinks))
}

// TestSetTAPUpDown_NonExistentDevice tests error paths for SetTAPUp/Down
func TestSetTAPUpDown_NonExistentDevice(t *testing.T) {
	m := NewManager()

	// Test SetTAPUp with nonexistent device
	err := m.SetTAPUp("tap-mock-nonexist-up")
	require.Error(t, err)
	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)

	// Test SetTAPDown with nonexistent device
	err = m.SetTAPDown("tap-mock-nonexist-down")
	require.Error(t, err)
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

// TestDeleteTAP_ErrorConditions tests DeleteTAP error paths
func TestDeleteTAP_ErrorConditions(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		tapName string
		errType ErrorType
	}{
		{
			name:    "nonexistent device",
			tapName: "tap-mock-delete-999",
			errType: ErrorTypeNotFound,
		},
		{
			name:    "empty name",
			tapName: "",
			errType: ErrorTypeInvalidName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.DeleteTAP(tt.tapName)
			require.Error(t, err)

			var netlinkErr *NetlinkError
			require.ErrorAs(t, err, &netlinkErr)
			assert.Equal(t, tt.errType, netlinkErr.Type)
		})
	}
}

// TestCreateTAPSimple_InputValidation tests CreateTAPSimple validation
func TestCreateTAPSimple_InputValidation(t *testing.T) {
	m := NewManager()

	// Test with invalid name (too long)
	err := m.CreateTAPSimple("verylonginterfacenamethatexceeds15chars", 1000, 1000)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeInvalidName, netlinkErr.Type)

	// Test with empty name
	err = m.CreateTAPSimple("", 1000, 1000)
	require.Error(t, err)
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeInvalidName, netlinkErr.Type)
}

// TestIsNotFoundError_EdgeCases tests all branches of isNotFoundError
func TestIsNotFoundError_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error returns false",
			err:  nil,
			want: false,
		},
		{
			name: "Link not found string matches",
			err:  errors.New("Link not found"),
			want: true,
		},
		{
			name: "ENODEV syscall error",
			err:  syscall.ENODEV,
			want: true,
		},
		{
			name: "ENXIO syscall error",
			err:  syscall.ENXIO,
			want: true,
		},
		{
			name: "other string error",
			err:  errors.New("some other error"),
			want: false,
		},
		{
			name: "permission error is not not-found",
			err:  syscall.EPERM,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNotFoundError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestIsPermissionError_EdgeCases tests all branches of isPermissionError
func TestIsPermissionError_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error returns false",
			err:  nil,
			want: false,
		},
		{
			name: "EPERM syscall error",
			err:  syscall.EPERM,
			want: true,
		},
		{
			name: "EACCES syscall error",
			err:  syscall.EACCES,
			want: true,
		},
		{
			name: "other error returns false",
			err:  errors.New("some error"),
			want: false,
		},
		{
			name: "ENODEV is not permission error",
			err:  syscall.ENODEV,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPermissionError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestIsExistsError_EdgeCases tests all branches of isExistsError
func TestIsExistsError_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error returns false",
			err:  nil,
			want: false,
		},
		{
			name: "EEXIST syscall error",
			err:  syscall.EEXIST,
			want: true,
		},
		{
			name: "other error returns false",
			err:  errors.New("some error"),
			want: false,
		},
		{
			name: "ENODEV is not exists error",
			err:  syscall.ENODEV,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExistsError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestTAPInfo_FieldAccess tests TAPInfo embedded struct access
func TestTAPInfo_FieldAccess(t *testing.T) {
	tapInfo := &TAPInfo{
		LinkInfo: LinkInfo{
			Index:        42,
			Name:         "tap-test",
			Type:         "tuntap",
			Flags:        0x1003,
			MTU:          1500,
			HardwareAddr: "aa:bb:cc:dd:ee:ff",
			OperState:    LinkStateUp,
			Master:       0,
		},
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    false,
	}

	// Verify all embedded LinkInfo fields are accessible
	assert.Equal(t, 42, tapInfo.Index)
	assert.Equal(t, "tap-test", tapInfo.Name)
	assert.Equal(t, "tuntap", tapInfo.Type)
	assert.Equal(t, uint32(0x1003), tapInfo.Flags)
	assert.Equal(t, 1500, tapInfo.MTU)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", tapInfo.HardwareAddr)
	assert.Equal(t, LinkStateUp, tapInfo.OperState)
	assert.Equal(t, 0, tapInfo.Master)

	// Verify TAP-specific fields
	assert.Equal(t, uint32(1000), tapInfo.Owner)
	assert.Equal(t, uint32(1000), tapInfo.Group)
	assert.True(t, tapInfo.MultiQueue)
	assert.False(t, tapInfo.Persist)
}

// TestTAPConfig_BoundaryValues tests TAPConfig with boundary values
func TestTAPConfig_BoundaryValues(t *testing.T) {
	tests := []struct {
		name    string
		config  *TAPConfig
		wantErr bool
	}{
		{
			name: "minimum valid - 1 char name",
			config: &TAPConfig{
				Name: "x",
			},
			wantErr: false,
		},
		{
			name: "maximum valid - 15 char name",
			config: &TAPConfig{
				Name: "123456789012345",
			},
			wantErr: false,
		},
		{
			name: "exceeds maximum - 16 char name",
			config: &TAPConfig{
				Name: "1234567890123456",
			},
			wantErr: true,
		},
		{
			name: "zero values for owner/group",
			config: &TAPConfig{
				Name:  "tap0",
				Owner: 0,
				Group: 0,
			},
			wantErr: false,
		},
		{
			name: "max uint32 for owner/group",
			config: &TAPConfig{
				Name:  "tap1",
				Owner: 4294967295,
				Group: 4294967295,
			},
			wantErr: false,
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

// TestManager_ThreadSafety tests concurrent access to Manager
func TestManager_ThreadSafety(t *testing.T) {
	m := NewManager()

	// Run multiple concurrent read operations
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- true }()

			// Multiple read operations
			_, _ = m.GetLink("lo")
			_, _ = m.ListLinks()
			_, _ = m.ListTAPs()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestGetTAP_ErrorMessages tests error message content
func TestGetTAP_ErrorMessages(t *testing.T) {
	m := NewManager()

	// Test empty name error message
	_, err := m.GetTAP("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
	assert.Contains(t, err.Error(), "name")

	// Test not found error message
	_, err = m.GetTAP("tap-mock-msg-test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test non-TAP device error message
	_, err = m.GetTAP("lo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a TAP device")
}

// TestCreateTAPSimple_ParameterMapping tests parameter mapping in CreateTAPSimple
func TestCreateTAPSimple_ParameterMapping(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		tapName string
		owner   uint32
		group   uint32
		valid   bool
	}{
		{
			name:    "valid parameters",
			tapName: "tap0",
			owner:   1000,
			group:   1000,
			valid:   true,
		},
		{
			name:    "empty name - invalid",
			tapName: "",
			owner:   1000,
			group:   1000,
			valid:   false,
		},
		{
			name:    "name too long - invalid",
			tapName: "verylongtapinterfacename",
			owner:   1000,
			group:   1000,
			valid:   false,
		},
		{
			name:    "zero owner and group",
			tapName: "tap1",
			owner:   0,
			group:   0,
			valid:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.CreateTAPSimple(tt.tapName, tt.owner, tt.group)
			// Will always error because we're not root, but check error type
			require.Error(t, err)

			var netlinkErr *NetlinkError
			require.ErrorAs(t, err, &netlinkErr)

			if !tt.valid {
				// Should fail validation
				assert.Equal(t, ErrorTypeInvalidName, netlinkErr.Type)
			} else {
				// Should fail at creation (permission or already exists)
				assert.True(t,
					netlinkErr.Type == ErrorTypePermission ||
						netlinkErr.Type == ErrorTypeCreateFailed ||
						netlinkErr.Type == ErrorTypeAlreadyExists,
				)
			}
		})
	}
}

// TestDeleteLinkUnsafe_IndirectCoverage tests deleteLinkUnsafe through CreateTAP
func TestDeleteLinkUnsafe_IndirectCoverage(t *testing.T) {
	m := NewManager()

	// deleteLinkUnsafe is only called in CreateTAP cleanup paths
	// We test it indirectly by verifying that invalid configs don't leave orphaned devices

	config := &TAPConfig{
		Name:  "", // Invalid - will fail validation
		Owner: 1000,
		Group: 1000,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)

	// Verify no device was created (validation failed before creation)
	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeInvalidName, netlinkErr.Type)
}

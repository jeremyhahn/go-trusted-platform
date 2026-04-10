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
	vnl "github.com/vishvananda/netlink"
)

// TestCreateTAP_ErrorPaths tests error paths in CreateTAP
func TestCreateTAP_ErrorPaths(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("MTU set failure triggers cleanup", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					return nil, errors.New("Link not found")
				}
				return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
			},
			linkAddFn: func(link vnl.Link) error {
				return nil
			},
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				return syscall.EINVAL // Invalid MTU
			},
			linkDelFn: func(link vnl.Link) error {
				return nil // Cleanup succeeds
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:    "tap-clean",
			Owner:   1000,
			Group:   1000,
			MTU:     999999, // Invalid MTU
			Persist: true,
		}

		err := m.CreateTAP(config)
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("permission error on create", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("Link not found")
			},
			linkAddFn: func(link vnl.Link) error {
				return syscall.EPERM
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:  "tap-perm-test",
			Owner: 1000,
			Group: 1000,
		}

		err := m.CreateTAP(config)
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
	})

	t.Run("exists error on create", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:  "tap-exists-test",
			Owner: 1000,
			Group: 1000,
		}

		err := m.CreateTAP(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

// TestSetLinkUp_PermissionError_Mock tests permission error path using mocks
func TestSetLinkUp_PermissionError_Mock(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			return syscall.EPERM
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkUp("lo")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestSetLinkDown_PermissionError_Mock tests permission error path using mocks
func TestSetLinkDown_PermissionError_Mock(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			return syscall.EACCES
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkDown("lo")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestSetLinkMTU_PermissionError_Mock tests permission error path using mocks
func TestSetLinkMTU_PermissionError_Mock(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			return syscall.EPERM
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkMTU("lo", 1500)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestDeleteLink_PermissionError_Mock tests permission error path using mocks
func TestDeleteLink_PermissionError_Mock(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkDelFn: func(link vnl.Link) error {
			return syscall.EPERM
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteLink("lo")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestGetLink_ErrorPath tests the error path in GetLink
func TestGetLink_ErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("unexpected error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetLink("nonexistent-interface-12345")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
}

// TestGetTAP_NotTAPDevice_Coverage ensures the "not a TAP device" check is covered
func TestGetTAP_NotTAPDevice_Coverage(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetTAP("lo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a TAP device")
}

// TestGetTAP_ErrorPaths tests various error paths in GetTAP
func TestGetTAP_ErrorPaths(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("empty name", func(t *testing.T) {
		m := NewManager()
		_, err := m.GetTAP("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("not found", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("Link not found")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.GetTAP("tap-nonexistent-xyz")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("not a TAP device", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.GetTAP("lo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a TAP device")
	})
}

// TestListTAPs_ErrorPath tests error path in ListTAPs
func TestListTAPs_ErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkListFn: func() ([]vnl.Link, error) {
				return []vnl.Link{
					createDummyLink("lo"),
					createTuntapLink("tap0", vnl.TUNTAP_MODE_TAP),
				}, nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		taps, err := m.ListTAPs()
		require.NoError(t, err)
		require.NotNil(t, taps)
		assert.Len(t, taps, 1)
	})

	t.Run("list error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkListFn: func() ([]vnl.Link, error) {
				return nil, errors.New("list failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.ListTAPs()
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})
}

// TestListLinks_ErrorPath tests error path in ListLinks
func TestListLinks_ErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkListFn: func() ([]vnl.Link, error) {
				return []vnl.Link{
					createDummyLink("lo"),
					createDummyLink("eth0"),
				}, nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		links, err := m.ListLinks()
		require.NoError(t, err)
		require.NotNil(t, links)
		assert.Len(t, links, 2)
	})

	t.Run("list error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkListFn: func() ([]vnl.Link, error) {
				return nil, errors.New("list failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.ListLinks()
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})
}

// TestDeleteLinkUnsafe_Coverage ensures deleteLinkUnsafe is covered
func TestDeleteLinkUnsafe_Coverage(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("cleanup after MTU failure", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					return nil, errors.New("Link not found")
				}
				return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
			},
			linkAddFn: func(link vnl.Link) error {
				return nil
			},
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				return syscall.EINVAL
			},
			linkDelFn: func(link vnl.Link) error {
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:    "tap-unsafe",
			Owner:   1000,
			Group:   1000,
			MTU:     999999,
			Persist: true,
		}

		err := m.CreateTAP(config)
		require.Error(t, err)
	})

	t.Run("direct delete success", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
			linkDelFn: func(link vnl.Link) error {
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.deleteLinkUnsafe("test0")
		require.NoError(t, err)
	})
}

// TestTAPConfig_Validate_Coverage ensures all validation paths are covered
func TestTAPConfig_Validate_Coverage(t *testing.T) {
	tests := []struct {
		name    string
		config  *TAPConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &TAPConfig{
				Name:  "tap0",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			config: &TAPConfig{
				Name: "",
			},
			wantErr: true,
			errMsg:  "empty name",
		},
		{
			name: "name too long",
			config: &TAPConfig{
				Name: "1234567890123456", // 16 chars
			},
			wantErr: true,
			errMsg:  "too long",
		},
		{
			name: "exactly 15 chars",
			config: &TAPConfig{
				Name: "123456789012345", // 15 chars
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestErrorHelpers_EdgeCases tests edge cases in error helper functions
func TestErrorHelpers_EdgeCases(t *testing.T) {
	t.Run("isNotFoundError with nil", func(t *testing.T) {
		assert.False(t, isNotFoundError(nil))
	})

	t.Run("isNotFoundError with ENODEV", func(t *testing.T) {
		assert.True(t, isNotFoundError(syscall.ENODEV))
	})

	t.Run("isNotFoundError with ENXIO", func(t *testing.T) {
		assert.True(t, isNotFoundError(syscall.ENXIO))
	})

	t.Run("isPermissionError with nil", func(t *testing.T) {
		assert.False(t, isPermissionError(nil))
	})

	t.Run("isPermissionError with EPERM", func(t *testing.T) {
		assert.True(t, isPermissionError(syscall.EPERM))
	})

	t.Run("isPermissionError with EACCES", func(t *testing.T) {
		assert.True(t, isPermissionError(syscall.EACCES))
	})

	t.Run("isExistsError with nil", func(t *testing.T) {
		assert.False(t, isExistsError(nil))
	})

	t.Run("isExistsError with EEXIST", func(t *testing.T) {
		assert.True(t, isExistsError(syscall.EEXIST))
	})
}

// TestCreateTAP_MultiQueue tests multi-queue TAP creation paths
func TestCreateTAP_MultiQueue(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			require.True(t, ok)
			assert.True(t, (tuntap.Flags&vnl.TUNTAP_MULTI_QUEUE_DEFAULTS) != 0)
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:       "tap-mq-test",
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    false,
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestCreateTAP_AllOptions tests all configuration options
func TestCreateTAP_AllOptions(t *testing.T) {
	defer ResetNetlinkOps()

	callCount := 0
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("Link not found")
			}
			tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
			tuntap.MTU = 1400
			return tuntap, nil
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			require.True(t, ok)
			assert.True(t, (tuntap.Flags&vnl.TUNTAP_MULTI_QUEUE_DEFAULTS) != 0)
			assert.False(t, tuntap.NonPersist) // Persist = true means NonPersist = false
			return nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			assert.Equal(t, 1400, mtu)
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:       "tap-all-opts",
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    true,
		MTU:        1400,
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestGetTAP_TUNDevice tests GetTAP with TUN device
func TestGetTAP_TUNDevice(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createTuntapLink(name, vnl.TUNTAP_MODE_TUN), nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetTAP("tun-test-tap")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TUN")
}

// TestListTAPs_WithMixedDevices tests ListTAPs with mixed device types
func TestListTAPs_WithMixedDevices(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				createDummyLink("lo"),
				createDummyLink("eth0"),
				createTuntapLink("tap-list-test", vnl.TUNTAP_MODE_TAP),
				createTuntapLink("tun-list-test", vnl.TUNTAP_MODE_TUN),
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	taps, err := m.ListTAPs()
	require.NoError(t, err)

	foundTAP := false
	foundTUN := false
	for _, tap := range taps {
		if tap.Name == "tap-list-test" {
			foundTAP = true
		}
		if tap.Name == "tun-list-test" {
			foundTUN = true
		}
	}

	assert.True(t, foundTAP, "Should find TAP device")
	assert.False(t, foundTUN, "Should not find TUN device in TAP list")
}

// TestCreateTAP_ZeroMTU tests TAP creation with zero MTU (default)
func TestCreateTAP_ZeroMTU(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    "tap-zero-mtu",
		Owner:   1000,
		Group:   1000,
		MTU:     0, // Should skip MTU setting
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

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

// TestSetLinkUp_PermissionPath specifically tests permission error path
func TestSetLinkUp_PermissionPath(t *testing.T) {
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

// TestSetLinkDown_PermissionPath specifically tests permission error path
func TestSetLinkDown_PermissionPath(t *testing.T) {
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

// TestSetLinkMTU_PermissionPath specifically tests permission error path
func TestSetLinkMTU_PermissionPath(t *testing.T) {
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

// TestDeleteLink_PermissionPath specifically tests permission error path
func TestDeleteLink_PermissionPath(t *testing.T) {
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

// TestGetLink_NotFoundErrorPath tests GetLink with non-existent interface
func TestGetLink_NotFoundErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetLink("thisinterfacedoesnotexist9999999")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

// TestGetTAP_SetupFailedPath tests GetTAP setup failed path
func TestGetTAP_SetupFailedPath(t *testing.T) {
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

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	assert.Contains(t, err.Error(), "not a TAP device")
}

// TestListLinks_SuccessPath tests successful listing
func TestListLinks_SuccessPath(t *testing.T) {
	defer ResetNetlinkOps()

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
	assert.Greater(t, len(links), 0, "Should have at least one link")

	// Verify loopback is present
	found := false
	for _, link := range links {
		if link.Name == "lo" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should find loopback interface")
}

// TestListTAPs_EmptySuccess tests successful listing with no TAPs
func TestListTAPs_EmptySuccess(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				createDummyLink("lo"),
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	taps, err := m.ListTAPs()
	require.NoError(t, err)
	require.NotNil(t, taps)
	assert.Len(t, taps, 0) // No TAP devices
}

// TestCreateTAP_EdgeCases tests edge cases in CreateTAP
func TestCreateTAP_EdgeCases(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("minimum MTU", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					return nil, errors.New("Link not found")
				}
				tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
				tuntap.MTU = 68
				return tuntap, nil
			},
			linkAddFn: func(link vnl.Link) error {
				return nil
			},
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				assert.Equal(t, 68, mtu)
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:    "tap-min-mtu",
			Owner:   1000,
			Group:   1000,
			MTU:     68, // Minimum valid MTU
			Persist: true,
		}

		err := m.CreateTAP(config)
		require.NoError(t, err)
	})

	t.Run("maximum MTU", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					return nil, errors.New("Link not found")
				}
				tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
				tuntap.MTU = 65536
				return tuntap, nil
			},
			linkAddFn: func(link vnl.Link) error {
				return nil
			},
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				assert.Equal(t, 65536, mtu)
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:    "tap-max-mtu",
			Owner:   1000,
			Group:   1000,
			MTU:     65536, // Maximum valid MTU
			Persist: true,
		}

		err := m.CreateTAP(config)
		require.NoError(t, err)
	})

	t.Run("owner 0 group 0", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					return nil, errors.New("Link not found")
				}
				tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
				tuntap.Owner = 0
				tuntap.Group = 0
				return tuntap, nil
			},
			linkAddFn: func(link vnl.Link) error {
				tuntap, ok := link.(*vnl.Tuntap)
				require.True(t, ok)
				assert.Equal(t, uint32(0), tuntap.Owner)
				assert.Equal(t, uint32(0), tuntap.Group)
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:    "tap-root-own",
			Owner:   0,
			Group:   0,
			Persist: true,
		}

		err := m.CreateTAP(config)
		require.NoError(t, err)
	})
}

// TestSetLinkMTU_BoundaryValues tests MTU boundary values
func TestSetLinkMTU_BoundaryValues(t *testing.T) {
	defer ResetNetlinkOps()

	currentMTU := 1500
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			dummy := &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   currentMTU,
				},
			}
			return dummy, nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			currentMTU = mtu
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Test minimum valid MTU (68)
	err := m.SetLinkMTU("tap-mtu-bound", 68)
	require.NoError(t, err)

	info, err := m.GetLink("tap-mtu-bound")
	require.NoError(t, err)
	assert.Equal(t, 68, info.MTU)

	// Test common MTU values
	for _, mtu := range []int{576, 1280, 1500, 9000} {
		err = m.SetLinkMTU("tap-mtu-bound", mtu)
		require.NoError(t, err)

		info, err = m.GetLink("tap-mtu-bound")
		require.NoError(t, err)
		assert.Equal(t, mtu, info.MTU)
	}
}

// TestCreateTAPSimple_AllPaths tests CreateTAPSimple wrapper
func TestCreateTAPSimple_AllPaths(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			require.True(t, ok)
			assert.False(t, (tuntap.Flags&vnl.TUNTAP_MULTI_QUEUE_DEFAULTS) != 0) // Not multi-queue
			assert.True(t, tuntap.NonPersist)
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.CreateTAPSimple("tap-simple2", 1000, 1000)
	require.NoError(t, err)
}

// TestDeleteTAP_Wrapper tests DeleteTAP wrapper function
func TestDeleteTAP_Wrapper(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
		},
		linkDelFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteTAP("tap-del-wrap")
	require.NoError(t, err)
}

// TestSetTAPUp_Wrapper tests SetTAPUp wrapper
func TestSetTAPUp_Wrapper(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetTAPUp("tap-up-wrap")
	require.NoError(t, err)
}

// TestSetTAPDown_Wrapper tests SetTAPDown wrapper
func TestSetTAPDown_Wrapper(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetTAPDown("tap-down-wrap")
	require.NoError(t, err)
}

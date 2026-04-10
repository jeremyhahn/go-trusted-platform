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

// TestCreateTAP_PermissionErrorPath tests permission error detection in CreateTAP
func TestCreateTAP_PermissionErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

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
		Name:    "tap-perm",
		Owner:   1000,
		Group:   1000,
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestCreateTAP_GetLinkAfterCreateFailure tests the error path where
// getting the link fails after creation
func TestCreateTAP_GetLinkAfterCreateFailure(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			// Always return not found - simulates failure to lookup after create
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:       "tap-get-fail",
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    false,
		MTU:        1400, // Will try to set MTU
	}

	err := m.CreateTAP(config)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
}

// TestSetLinkUp_GenericErrorPath tests generic error path in SetLinkUp
func TestSetLinkUp_GenericErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			return errors.New("generic error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkUp("tap-up-err")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeStateFailed, netlinkErr.Type)
}

// TestSetLinkUp_IdempotentSuccess tests that SetLinkUp is idempotent
func TestSetLinkUp_IdempotentSuccess(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Bring it up twice (should succeed - idempotent)
	err := m.SetLinkUp("tap-test")
	require.NoError(t, err)

	err = m.SetLinkUp("tap-test")
	require.NoError(t, err)
}

// TestSetLinkDown_GenericErrorPath tests generic error path in SetLinkDown
func TestSetLinkDown_GenericErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			return errors.New("generic error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkDown("tap-down-err")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeStateFailed, netlinkErr.Type)
}

// TestSetLinkDown_IdempotentSuccess tests that SetLinkDown is idempotent
func TestSetLinkDown_IdempotentSuccess(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Bring it down twice (should succeed - idempotent)
	err := m.SetLinkDown("tap-test")
	require.NoError(t, err)

	err = m.SetLinkDown("tap-test")
	require.NoError(t, err)
}

// TestSetLinkMTU_GenericErrorPath tests generic error path in SetLinkMTU
func TestSetLinkMTU_GenericErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			return errors.New("generic error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkMTU("tap-mtu-err", 1400)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
}

// TestSetLinkMTU_MultipleSuccess tests multiple MTU changes
func TestSetLinkMTU_MultipleSuccess(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Set multiple MTU values
	err := m.SetLinkMTU("tap-test", 1400)
	require.NoError(t, err)

	err = m.SetLinkMTU("tap-test", 1500)
	require.NoError(t, err)
}

// TestDeleteLink_GenericErrorPath tests generic error path in DeleteLink
func TestDeleteLink_GenericErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkDelFn: func(link vnl.Link) error {
			return errors.New("generic error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteLink("tap-del-err")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeDeleteFailed, netlinkErr.Type)
}

// TestDeleteLink_SuccessPath tests successful delete
func TestDeleteLink_MockedSuccessPath(t *testing.T) {
	defer ResetNetlinkOps()

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

	err := m.DeleteLink("tap-del")
	require.NoError(t, err)
}

// TestListLinks_SuccessWithMock tests ListLinks success path with mocks
func TestListLinks_SuccessWithMock(t *testing.T) {
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
	assert.Len(t, links, 2)
}

// TestListTAPs_SuccessPath tests ListTAPs success path
func TestListTAPs_SuccessPath(t *testing.T) {
	defer ResetNetlinkOps()

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
}

// TestGetTAP_GenericErrorPath tests GetTAP generic error path
func TestGetTAP_GenericErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("unexpected error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetTAP("tap-get-gen")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
}

// TestGetTAP_SuccessPath tests GetTAP success path
func TestGetTAP_SuccessPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	info, err := m.GetTAP("tap-get-gen")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "tap-get-gen", info.Name)
}

// TestDeleteLinkUnsafe_MockedErrorPath tests deleteLinkUnsafe error path with mocks
func TestDeleteLinkUnsafe_MockedErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.deleteLinkUnsafe("nonexistent")
	require.Error(t, err)
}

// TestCreateTAP_ExistsErrorAfterCheck tests the exists error path in LinkAdd
func TestCreateTAP_ExistsErrorAfterCheck(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			// Device already exists
			return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    "tap-exists",
		Owner:   1000,
		Group:   1000,
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// TestCreateTAP_MassiveInvalidMTU tests MTU failure cleanup path
func TestCreateTAP_MassiveInvalidMTU(t *testing.T) {
	defer ResetNetlinkOps()

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
		Name:    "tap-badmtu2",
		Owner:   1000,
		Group:   1000,
		MTU:     2000000, // Extremely large
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)
}

// TestGetLink_GenericError tests GetLink generic error path
func TestGetLink_GenericError(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetLink("nonexist-link-xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestCreateTAP_CreateSuccessPath tests successful TAP creation
func TestCreateTAP_CreateSuccessPath(t *testing.T) {
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
		Name:    "tap-create",
		Owner:   1000,
		Group:   1000,
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestCreateTAP_NonPersistentWithoutMTU tests creating non-persistent TAP
func TestCreateTAP_NonPersistentWithoutMTU(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			require.True(t, ok)
			assert.True(t, tuntap.NonPersist) // NonPersist = true
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:       "tap-nonpers",
		Owner:      1000,
		Group:      1000,
		MultiQueue: false,
		Persist:    false, // Non-persistent
		MTU:        0,     // No MTU setting
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestCreateTAP_WithVerySmallMTU tests small but valid MTU
func TestCreateTAP_WithVerySmallMTU(t *testing.T) {
	defer ResetNetlinkOps()

	callCount := 0
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("Link not found")
			}
			tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
			tuntap.MTU = 576
			return tuntap, nil
		},
		linkAddFn: func(link vnl.Link) error {
			return nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			assert.Equal(t, 576, mtu)
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    "tap-smallmtu",
		Owner:   1000,
		Group:   1000,
		MTU:     576, // Minimum for IPv4
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestListTAPs_WithRealTUN tests ListTAPs filtering out TUN devices
func TestListTAPs_WithRealTUN(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				createTuntapLink("tap-list2", vnl.TUNTAP_MODE_TAP),
				createTuntapLink("tun-list2", vnl.TUNTAP_MODE_TUN),
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
		if tap.Name == "tap-list2" {
			foundTAP = true
		}
		if tap.Name == "tun-list2" {
			foundTUN = true
		}
	}

	assert.True(t, foundTAP, "Should find TAP device")
	assert.False(t, foundTUN, "Should not find TUN device")
}

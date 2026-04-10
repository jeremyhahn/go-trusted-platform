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
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

// TestCreateTAP_MTUFailureCleanup_Mock tests the cleanup path when MTU setting fails
// This covers the deleteLinkUnsafe error path in CreateTAP (lines 59-60, 65-66)
func TestCreateTAP_MTUFailureCleanup_Mock(t *testing.T) {
	defer ResetNetlinkOps()

	// Simulate MTU setting failure which triggers cleanup
	callCount := 0
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			callCount++
			if callCount == 1 {
				// First call: exists check - not found
				return nil, errors.New("Link not found")
			}
			// Second call: lookup for MTU setting
			return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
		},
		linkAddFn: func(link vnl.Link) error {
			return nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			return syscall.EINVAL // MTU setting fails
		},
		linkDelFn: func(link vnl.Link) error {
			return nil // Cleanup succeeds
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    "tap-mtu-fail",
		Owner:   1000,
		Group:   1000,
		MTU:     1400,
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
}

// TestCreateTAP_MultiQueueBranch tests the multi-queue flag setting branch
func TestCreateTAP_MultiQueueBranch(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			// Verify multi-queue flag is set
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
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestCreateTAP_PermissionErrorBranch tests permission error detection (line 45-47)
func TestCreateTAP_PermissionErrorBranch(t *testing.T) {
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
		Name:  "tap-perm-test",
		Owner: 1000,
		Group: 1000,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestSetLinkUp_PermissionError tests the permission error branch in SetLinkUp (line 61-63)
func TestSetLinkUp_PermissionError(t *testing.T) {
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

// TestSetLinkDown_PermissionError tests the permission error branch in SetLinkDown (line 88-90)
func TestSetLinkDown_PermissionError(t *testing.T) {
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

// TestSetLinkMTU_PermissionError tests the permission error branch in SetLinkMTU (line 119-121)
func TestSetLinkMTU_PermissionError(t *testing.T) {
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

	err := m.SetLinkMTU("lo", 1400)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
}

// TestDeleteLink_PermissionError tests the permission error branch in DeleteLink (line 146-148)
func TestDeleteLink_PermissionError(t *testing.T) {
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

// TestGetTAP_SetupFailedBranch tests the setup failed error branch in GetTAP (line 106)
func TestGetTAP_SetupFailedBranch(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			// Return a non-tuntap device
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

// TestGetLink_SetupFailedBranch tests the setup failed error path in GetLink (line 37)
func TestGetLink_SetupFailedBranch(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("unexpected error")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetLink("nonexistent-interface-with-long-name-99999")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
}

// TestSetLinkUp_SetupFailedBranch tests the setup failed error path in SetLinkUp (line 57)
func TestSetLinkUp_SetupFailedBranch(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkUp("invalid-interface-name-99999")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

// TestSetLinkDown_SetupFailedBranch tests the setup failed error path in SetLinkDown (line 84)
func TestSetLinkDown_SetupFailedBranch(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkDown("invalid-interface-name-99999")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

// TestSetLinkMTU_SetupFailedBranch tests the setup failed error path in SetLinkMTU (line 115)
func TestSetLinkMTU_SetupFailedBranch(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkMTU("invalid-interface-name-99999", 1500)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

// TestDeleteLinkUnsafe_ErrorPath tests the error path in deleteLinkUnsafe
func TestDeleteLinkUnsafe_ErrorPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteLink("nonexistent-interface-99999")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

// TestListLinks_Coverage ensures ListLinks is covered
func TestListLinks_Coverage(t *testing.T) {
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
	require.NotEmpty(t, links)

	found := false
	for _, link := range links {
		assert.NotEmpty(t, link.Name)
		assert.Greater(t, link.Index, 0)
		if link.Name == "lo" {
			found = true
		}
	}
	assert.True(t, found, "Should find loopback interface")
}

// TestListTAPs_Coverage ensures ListTAPs is covered
func TestListTAPs_Coverage(t *testing.T) {
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
	assert.Equal(t, "tap0", taps[0].Name)
}

// TestIsNotFoundError_AllPaths tests all branches of isNotFoundError
func TestIsNotFoundError_AllPaths(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "ENODEV",
			err:  syscall.ENODEV,
			want: true,
		},
		{
			name: "ENXIO",
			err:  syscall.ENXIO,
			want: true,
		},
		{
			name: "Link not found string",
			err:  errors.New("Link not found"),
			want: true,
		},
		{
			name: "other syscall error",
			err:  syscall.EINVAL,
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

// TestIsPermissionError_AllPaths tests all branches of isPermissionError
func TestIsPermissionError_AllPaths(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "EPERM",
			err:  syscall.EPERM,
			want: true,
		},
		{
			name: "EACCES",
			err:  syscall.EACCES,
			want: true,
		},
		{
			name: "other error",
			err:  syscall.EINVAL,
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

// TestIsExistsError_AllPaths tests all branches of isExistsError
func TestIsExistsError_AllPaths(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "EEXIST",
			err:  syscall.EEXIST,
			want: true,
		},
		{
			name: "other error",
			err:  syscall.EINVAL,
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

// TestCreateTAP_ExistsErrorBranch tests the exists error detection in CreateTAP (line 48-50)
func TestCreateTAP_ExistsErrorBranch(t *testing.T) {
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
		Name:    "tap-exists-test",
		Owner:   1000,
		Group:   1000,
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeAlreadyExists, netlinkErr.Type)
}

// TestCreateTAP_MTUSettingSuccess tests successful MTU setting path (line 55-68)
func TestCreateTAP_MTUSettingSuccess(t *testing.T) {
	defer ResetNetlinkOps()

	callCount := 0
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			callCount++
			if callCount == 1 {
				// First call: exists check
				return nil, errors.New("Link not found")
			}
			// Second call: for MTU setting
			tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
			tuntap.MTU = 9000
			return tuntap, nil
		},
		linkAddFn: func(link vnl.Link) error {
			return nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			assert.Equal(t, 9000, mtu)
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    "tap-mtu-success",
		Owner:   1000,
		Group:   1000,
		MTU:     9000,
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.NoError(t, err)
}

// TestGetTAP_NotTAPDeviceBranch tests the "not a TAP device" branches (line 112, 116)
func TestGetTAP_NotTAPDeviceBranch(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("not a tuntap device", func(t *testing.T) {
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
	})

	t.Run("is TUN not TAP", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createTuntapLink(name, vnl.TUNTAP_MODE_TUN), nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.GetTAP("tun-not-tap")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
		assert.Contains(t, err.Error(), "TUN")
	})
}

// TestConcurrentLinkOperations tests thread safety of link operations
func TestConcurrentLinkOperations(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{createDummyLink("lo")}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	done := make(chan bool, 20)

	// Launch multiple concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				_, _ = m.GetLink("lo")
			}
		}()
	}

	// Launch multiple concurrent list operations
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				_, _ = m.ListLinks()
			}
		}()
	}

	// Wait for all to complete
	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestLinkToInfo_NilHardwareAddr ensures the nil hardware address branch is covered
func TestLinkToInfo_NilHardwareAddr(t *testing.T) {
	// Create a dummy link with nil hardware address
	dummy := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:        1,
			Name:         "test0",
			HardwareAddr: nil,
			OperState:    vnl.OperUp,
		},
	}

	info := linkToInfo(dummy)
	assert.Equal(t, "", info.HardwareAddr)
}

// TestLinkToInfo_ValidHardwareAddr ensures the hardware address branch is covered
func TestLinkToInfo_ValidHardwareAddr(t *testing.T) {
	defer ResetNetlinkOps()

	// Create a link with valid hardware address
	dummy := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:        1,
			Name:         "eth0",
			MTU:          1500,
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			OperState:    vnl.OperUp,
		},
	}

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return dummy, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	info, err := m.GetLink("eth0")
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "00:11:22:33:44:55", info.HardwareAddr)
}

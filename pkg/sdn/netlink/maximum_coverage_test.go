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

// TestComprehensive_AllOperations exercises all code paths
func TestComprehensive_AllOperations(t *testing.T) {
	defer ResetNetlinkOps()

	// Test 1: Create TAP with all combinations
	t.Run("create_and_verify", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					return nil, errors.New("Link not found")
				}
				tuntap := createTuntapLink(name, vnl.TUNTAP_MODE_TAP)
				tuntap.MTU = 1500
				return tuntap, nil
			},
			linkAddFn: func(link vnl.Link) error {
				return nil
			},
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:       "tap-comp1",
			Owner:      1000,
			Group:      1000,
			MultiQueue: false,
			Persist:    true,
			MTU:        1500,
		}

		err := m.CreateTAP(config)
		require.NoError(t, err)
	})

	// Test 2: Link state changes
	t.Run("link_state_changes", func(t *testing.T) {
		isUp := false
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				dummy := createDummyLink(name)
				if isUp {
					dummy.Attrs().Flags = net.FlagUp
				} else {
					dummy.Attrs().Flags = 0
				}
				return dummy, nil
			},
			linkSetUpFn: func(link vnl.Link) error {
				isUp = true
				return nil
			},
			linkSetDownFn: func(link vnl.Link) error {
				isUp = false
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		// Down -> Up -> Down sequence
		err := m.SetLinkDown("tap-comp2")
		require.NoError(t, err)

		err = m.SetLinkUp("tap-comp2")
		require.NoError(t, err)

		info, err := m.GetLink("tap-comp2")
		require.NoError(t, err)
		assert.True(t, IsUp(info.Flags))

		err = m.SetLinkDown("tap-comp2")
		require.NoError(t, err)

		info, err = m.GetLink("tap-comp2")
		require.NoError(t, err)
		assert.False(t, IsUp(info.Flags))
	})

	// Test 3: MTU changes
	t.Run("mtu_changes", func(t *testing.T) {
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

		// Try multiple MTU values
		for _, mtu := range []int{68, 500, 1500, 9000} {
			err := m.SetLinkMTU("tap-comp3", mtu)
			require.NoError(t, err)

			info, err := m.GetLink("tap-comp3")
			require.NoError(t, err)
			assert.Equal(t, mtu, info.MTU)
		}
	})

	// Test 4: List operations
	t.Run("list_operations", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkListFn: func() ([]vnl.Link, error) {
				return []vnl.Link{
					createDummyLink("lo"),
					createTuntapLink("tap-comp4", vnl.TUNTAP_MODE_TAP),
				}, nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		// List all links
		links, err := m.ListLinks()
		require.NoError(t, err)
		assert.Greater(t, len(links), 0)

		// List TAPs
		taps, err := m.ListTAPs()
		require.NoError(t, err)

		// Find our TAP
		found := false
		for _, tap := range taps {
			if tap.Name == "tap-comp4" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	// Test 5: Delete operation
	t.Run("delete_operation", func(t *testing.T) {
		deleted := false
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				if deleted {
					return nil, errors.New("Link not found")
				}
				return createDummyLink(name), nil
			},
			linkDelFn: func(link vnl.Link) error {
				deleted = true
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		// Delete
		err := m.DeleteLink("tap-comp5")
		require.NoError(t, err)

		// Verify gone
		_, err = m.GetLink("tap-comp5")
		require.Error(t, err)
	})

	// Test 6: Error conditions
	t.Run("error_conditions", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				if name == "tap-comp6" {
					return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
				}
				return nil, errors.New("Link not found")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		// Already exists
		config := &TAPConfig{
			Name:    "tap-comp6",
			Owner:   1000,
			Group:   1000,
			Persist: true,
		}

		err := m.CreateTAP(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")

		// Not found
		_, err = m.GetLink("nonexistent-if-999")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		// Invalid name
		_, err = m.GetLink("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	// Test 7: Multi-queue TAP
	t.Run("multiqueue_tap", func(t *testing.T) {
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
			Name:       "tap-comp7",
			Owner:      1000,
			Group:      1000,
			MultiQueue: true,
			Persist:    false,
		}

		err := m.CreateTAP(config)
		require.NoError(t, err)
	})

	// Test 8: TUN device filtering
	t.Run("tun_device_filtering", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createTuntapLink(name, vnl.TUNTAP_MODE_TUN), nil
			},
			linkListFn: func() ([]vnl.Link, error) {
				return []vnl.Link{
					createTuntapLink("tun-comp", vnl.TUNTAP_MODE_TUN),
				}, nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		// Try to get as TAP
		_, err := m.GetTAP("tun-comp")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TUN")

		// List TAPs should not include TUN
		taps, err := m.ListTAPs()
		require.NoError(t, err)

		for _, tap := range taps {
			assert.NotEqual(t, "tun-comp", tap.Name)
		}
	})

	// Test 9: Wrapper functions
	t.Run("wrapper_functions", func(t *testing.T) {
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
			linkSetUpFn: func(link vnl.Link) error {
				return nil
			},
			linkSetDownFn: func(link vnl.Link) error {
				return nil
			},
			linkDelFn: func(link vnl.Link) error {
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		config := &TAPConfig{
			Name:    "tap-comp9",
			Owner:   1000,
			Group:   1000,
			Persist: true,
		}
		err := m.CreateTAP(config)
		require.NoError(t, err)

		// SetTAPUp
		err = m.SetTAPUp("tap-comp9")
		require.NoError(t, err)

		// SetTAPDown
		err = m.SetTAPDown("tap-comp9")
		require.NoError(t, err)

		// DeleteTAP
		err = m.DeleteTAP("tap-comp9")
		require.NoError(t, err)
	})

	// Test 10: Flag helpers
	t.Run("flag_helpers", func(t *testing.T) {
		isUp := false
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				dummy := createDummyLink(name)
				if isUp {
					dummy.Attrs().Flags = net.FlagUp
				} else {
					dummy.Attrs().Flags = 0
				}
				return dummy, nil
			},
			linkSetUpFn: func(link vnl.Link) error {
				isUp = true
				return nil
			},
			linkSetDownFn: func(link vnl.Link) error {
				isUp = false
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()

		// Bring it up
		err := m.SetLinkUp("tap-comp10")
		require.NoError(t, err)

		info, err := m.GetLink("tap-comp10")
		require.NoError(t, err)
		assert.True(t, IsUp(info.Flags))

		// Bring it down
		err = m.SetLinkDown("tap-comp10")
		require.NoError(t, err)

		info, err = m.GetLink("tap-comp10")
		require.NoError(t, err)
		assert.False(t, IsUp(info.Flags))
	})
}

// TestAllValidationPaths tests all validation code paths
func TestAllValidationPaths(t *testing.T) {
	m := NewManager()

	t.Run("GetLink validation", func(t *testing.T) {
		_, err := m.GetLink("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("SetLinkUp validation", func(t *testing.T) {
		err := m.SetLinkUp("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("SetLinkDown validation", func(t *testing.T) {
		err := m.SetLinkDown("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("SetLinkMTU validation", func(t *testing.T) {
		// Empty name
		err := m.SetLinkMTU("", 1500)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")

		// Invalid MTU - too small
		err = m.SetLinkMTU("lo", 1)
		require.Error(t, err)

		// Invalid MTU - too large
		err = m.SetLinkMTU("lo", 999999)
		require.Error(t, err)
	})

	t.Run("DeleteLink validation", func(t *testing.T) {
		err := m.DeleteLink("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("GetTAP validation", func(t *testing.T) {
		_, err := m.GetTAP("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("TAPConfig validation", func(t *testing.T) {
		// Empty name
		config := &TAPConfig{Name: ""}
		err := config.Validate()
		require.Error(t, err)

		// Too long name
		config = &TAPConfig{Name: "verylonginterfacenamethatisinvalid"}
		err = config.Validate()
		require.Error(t, err)

		// Valid name
		config = &TAPConfig{Name: "tap0"}
		err = config.Validate()
		require.NoError(t, err)
	})
}

// TestSetLinkMTU_InvalidValues tests invalid MTU values
func TestSetLinkMTU_InvalidValues(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return createDummyLink(name), nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Test invalid MTU - too small
	err := m.SetLinkMTU("tap-test", 1)
	require.Error(t, err)

	// Test invalid MTU - too large
	err = m.SetLinkMTU("tap-test", 999999)
	require.Error(t, err)

	// Test invalid MTU - negative (will be caught as too small)
	err = m.SetLinkMTU("tap-test", -1)
	require.Error(t, err)
}

// TestOperStateConversion tests OperState conversion
func TestOperStateConversion(t *testing.T) {
	states := []vnl.LinkOperState{
		vnl.OperUp,
		vnl.OperDown,
		vnl.OperUnknown,
		vnl.OperNotPresent,
		vnl.OperLowerLayerDown,
		vnl.OperTesting,
		vnl.OperDormant,
	}

	for _, state := range states {
		dummy := &vnl.Dummy{
			LinkAttrs: vnl.LinkAttrs{
				Index:     1,
				Name:      "test",
				OperState: state,
			},
		}
		info := linkToInfo(dummy)
		// Just ensure no panic and a valid state is returned
		assert.NotEmpty(t, string(info.OperState))
	}
}

// TestLinkWithHardwareAddr tests hardware address handling
func TestLinkWithHardwareAddr(t *testing.T) {
	// Test with valid hardware address
	dummy := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:        1,
			Name:         "eth0",
			HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
	}
	info := linkToInfo(dummy)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", info.HardwareAddr)

	// Test with nil hardware address
	dummy.HardwareAddr = nil
	info = linkToInfo(dummy)
	assert.Equal(t, "", info.HardwareAddr)

	// Test with empty hardware address
	dummy.HardwareAddr = net.HardwareAddr{}
	info = linkToInfo(dummy)
	assert.Equal(t, "", info.HardwareAddr)
}

// TestDeleteLinkLookupError tests delete when lookup fails
func TestDeleteLinkLookupError(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, syscall.ENODEV
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteLink("nonexistent")
	require.Error(t, err)

	var netlinkErr *NetlinkError
	require.ErrorAs(t, err, &netlinkErr)
	assert.Equal(t, ErrorTypeNotFound, netlinkErr.Type)
}

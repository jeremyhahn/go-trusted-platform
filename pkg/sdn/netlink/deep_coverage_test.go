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

// TestGetLink_AllErrorPaths tests all error paths in GetLink
func TestGetLink_AllErrorPaths(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()

	t.Run("empty name", func(t *testing.T) {
		_, err := m.GetLink("")
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

		_, err := m.GetLink("extremely-unlikely-interface-name-999")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("success - loopback", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return &vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 1,
						Name:  "lo",
						MTU:   65536,
					},
				}, nil
			},
		}
		SetNetlinkOps(mock)

		info, err := m.GetLink("lo")
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, "lo", info.Name)
	})
}

// TestSetLinkUp_AllPaths tests all paths in SetLinkUp using mocks
func TestSetLinkUp_AllPaths(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()
	tapName := "tap-setup1"
	var linkUp bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			flags := net.Flags(0)
			if linkUp {
				flags = net.FlagUp
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500,
					Flags: flags,
				},
				Mode:  vnl.TUNTAP_MODE_TAP,
				Owner: 1000,
				Group: 1000,
			}, nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			linkUp = true
			return nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			linkUp = false
			return nil
		},
	}
	SetNetlinkOps(mock)

	// Bring it down first
	err := m.SetLinkDown(tapName)
	require.NoError(t, err)

	// Now test SetLinkUp
	err = m.SetLinkUp(tapName)
	require.NoError(t, err)

	// Verify it's up
	info, err := m.GetLink(tapName)
	require.NoError(t, err)
	assert.True(t, IsUp(info.Flags))

	// Test idempotent - set up when already up
	err = m.SetLinkUp(tapName)
	require.NoError(t, err)
}

// TestSetLinkDown_AllPaths tests all paths in SetLinkDown using mocks
func TestSetLinkDown_AllPaths(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()
	tapName := "tap-setup2"
	var linkUp = true

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			flags := net.Flags(0)
			if linkUp {
				flags = net.FlagUp
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500,
					Flags: flags,
				},
				Mode:  vnl.TUNTAP_MODE_TAP,
				Owner: 1000,
				Group: 1000,
			}, nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			linkUp = true
			return nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			linkUp = false
			return nil
		},
	}
	SetNetlinkOps(mock)

	// Bring it up first
	err := m.SetLinkUp(tapName)
	require.NoError(t, err)

	// Now test SetLinkDown
	err = m.SetLinkDown(tapName)
	require.NoError(t, err)

	// Verify it's down
	info, err := m.GetLink(tapName)
	require.NoError(t, err)
	assert.False(t, IsUp(info.Flags))

	// Test idempotent - set down when already down
	err = m.SetLinkDown(tapName)
	require.NoError(t, err)
}

// TestSetLinkMTU_AllPaths tests all paths in SetLinkMTU using mocks
func TestSetLinkMTU_AllPaths(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()
	tapName := "tap-setup3"
	var currentMTU = 1500

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   currentMTU,
				},
				Mode:  vnl.TUNTAP_MODE_TAP,
				Owner: 1000,
				Group: 1000,
			}, nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			currentMTU = mtu
			return nil
		},
	}
	SetNetlinkOps(mock)

	// Test setting various MTU values
	for _, mtu := range []int{576, 1280, 1500, 9000} {
		err := m.SetLinkMTU(tapName, mtu)
		require.NoError(t, err)

		info, err := m.GetLink(tapName)
		require.NoError(t, err)
		assert.Equal(t, mtu, info.MTU)
	}
}

// TestDeleteLink_AllPaths tests all paths in DeleteLink using mocks
func TestDeleteLink_AllPaths(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()
	tapName := "tap-setup4"
	var exists = true

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !exists {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500,
				},
				Mode:  vnl.TUNTAP_MODE_TAP,
				Owner: 1000,
				Group: 1000,
			}, nil
		},
		linkDelFn: func(link vnl.Link) error {
			exists = false
			return nil
		},
	}
	SetNetlinkOps(mock)

	// Delete the link
	err := m.DeleteLink(tapName)
	require.NoError(t, err)

	// Verify it's gone
	_, err = m.GetLink(tapName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestErrorHelpers_SystemErrors tests error helpers with actual syscall errors
func TestErrorHelpers_SystemErrors(t *testing.T) {
	t.Run("isNotFoundError with syscall errors", func(t *testing.T) {
		assert.True(t, isNotFoundError(syscall.ENODEV))
		assert.True(t, isNotFoundError(syscall.ENXIO))
		assert.False(t, isNotFoundError(syscall.EINVAL))
		assert.False(t, isNotFoundError(nil))
	})

	t.Run("isPermissionError with syscall errors", func(t *testing.T) {
		assert.True(t, isPermissionError(syscall.EPERM))
		assert.True(t, isPermissionError(syscall.EACCES))
		assert.False(t, isPermissionError(syscall.EINVAL))
		assert.False(t, isPermissionError(nil))
	})

	t.Run("isExistsError with syscall errors", func(t *testing.T) {
		assert.True(t, isExistsError(syscall.EEXIST))
		assert.False(t, isExistsError(syscall.EINVAL))
		assert.False(t, isExistsError(nil))
	})
}

// TestCreateTAP_AllConfigCombinations tests various config combinations using mocks
func TestCreateTAP_AllConfigCombinations(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()

	tests := []struct {
		name       string
		tapName    string
		multiQueue bool
		persist    bool
		mtu        int
	}{
		{"mq persist", "tap-mqp", true, true, 0},
		{"mq nopersist", "tap-mqnp", true, false, 0},
		{"nomq persist", "tap-nmqp", false, true, 0},
		{"nomq nopersist", "tap-nmqnp", false, false, 0},
		{"with mtu", "tap-mtu1", false, true, 1400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var created bool
			var setMTU int

			mock := &mockNetlinkOps{
				linkByNameFn: func(name string) (vnl.Link, error) {
					if !created {
						return nil, errors.New("Link not found")
					}
					mtu := 1500
					if setMTU > 0 {
						mtu = setMTU
					}
					return &vnl.Tuntap{
						LinkAttrs: vnl.LinkAttrs{
							Index: 1,
							Name:  name,
							MTU:   mtu,
						},
						Mode: vnl.TUNTAP_MODE_TAP,
						Flags: func() vnl.TuntapFlag {
							if tt.multiQueue {
								return vnl.TUNTAP_MULTI_QUEUE
							} else {
								return 0
							}
						}(),
						Owner:      1000,
						Group:      1000,
						NonPersist: !tt.persist,
					}, nil
				},
				linkAddFn: func(link vnl.Link) error {
					created = true
					return nil
				},
				linkSetMTUFn: func(link vnl.Link, mtu int) error {
					setMTU = mtu
					return nil
				},
				linkDelFn: func(link vnl.Link) error {
					created = false
					return nil
				},
			}
			SetNetlinkOps(mock)

			config := &TAPConfig{
				Name:       tt.tapName,
				Owner:      1000,
				Group:      1000,
				MultiQueue: tt.multiQueue,
				Persist:    tt.persist,
				MTU:        tt.mtu,
			}

			err := m.CreateTAP(config)
			require.NoError(t, err)

			// Verify
			info, err := m.GetTAP(tt.tapName)
			require.NoError(t, err)
			assert.Equal(t, tt.tapName, info.Name)
			if tt.mtu > 0 {
				assert.Equal(t, tt.mtu, info.MTU)
			}
		})
	}
}

// TestListLinks_Coverage tests ListLinks coverage using mocks
func TestListLinks_CompleteCoverage(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				&vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 1,
						Name:  "lo",
						MTU:   65536,
					},
				},
				&vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 2,
						Name:  "eth0",
						MTU:   1500,
					},
				},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	links, err := m.ListLinks()
	require.NoError(t, err)
	require.NotNil(t, links)
	assert.Equal(t, 2, len(links))

	// Verify all links have required fields
	for _, link := range links {
		assert.Greater(t, link.Index, 0)
		assert.NotEmpty(t, link.Name)
		assert.NotEmpty(t, link.Type)
	}
}

// TestListTAPs_Coverage tests ListTAPs coverage using mocks
func TestListTAPs_CompleteCoverage(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				&vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "lo"}},
				&vnl.Tuntap{
					LinkAttrs: vnl.LinkAttrs{Name: "tap0"},
					Mode:      vnl.TUNTAP_MODE_TAP,
				},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	taps, err := m.ListTAPs()
	require.NoError(t, err)
	require.NotNil(t, taps)
	assert.Equal(t, 1, len(taps))
}

// TestGetTAP_Coverage tests GetTAP coverage using mocks
func TestGetTAP_AllCoverage(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()

	t.Run("empty name", func(t *testing.T) {
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

		_, err := m.GetTAP("tap-nonexistent-xyz-999")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("not a tap", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return &vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 1,
						Name:  name,
					},
				}, nil
			},
		}
		SetNetlinkOps(mock)

		_, err := m.GetTAP("lo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a TAP device")
	})
}

// TestCreateTAP_MTUFailureCleanup tests MTU failure cleanup using mocks
func TestCreateTAP_MTUFailureCleanup(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()
	tapName := "tap-cleanup"
	var cleaned bool
	callCount := 0

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
				},
				Mode: vnl.TUNTAP_MODE_TAP,
			}, nil
		},
		linkAddFn: func(link vnl.Link) error {
			return nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			return errors.New("invalid MTU: too large")
		},
		linkDelFn: func(link vnl.Link) error {
			cleaned = true
			return nil
		},
	}
	SetNetlinkOps(mock)

	// Try to create with extremely large MTU
	config := &TAPConfig{
		Name:    tapName,
		Owner:   1000,
		Group:   1000,
		MTU:     5000000, // Will fail
		Persist: true,
	}

	err := m.CreateTAP(config)
	require.Error(t, err)
	assert.True(t, cleaned, "Device should be cleaned up after MTU failure")
}

// TestNetlinkError_ErrorInterface tests NetlinkError implements error interface correctly
func TestNetlinkError_ErrorInterface(t *testing.T) {
	var _ error = (*NetlinkError)(nil)

	err := &NetlinkError{
		Type:    ErrorTypeInvalidName,
		Message: "test",
		Cause:   nil,
	}

	assert.NotEmpty(t, err.Error())
	assert.Contains(t, err.Error(), "invalid_name")
	assert.Contains(t, err.Error(), "test")
}

// TestNewManager_Concurrent tests concurrent manager access using mocks
func TestNewManager_Concurrent(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   65536,
				},
			}, nil
		},
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				&vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "lo"}},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			for j := 0; j < 50; j++ {
				_, _ = m.ListLinks()
				_, _ = m.GetLink("lo")
				_, _ = m.ListTAPs()
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

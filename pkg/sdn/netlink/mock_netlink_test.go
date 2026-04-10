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

// mockNetlinkOps implements NetlinkOps for testing
type mockNetlinkOps struct {
	linkByNameFn  func(name string) (vnl.Link, error)
	linkAddFn     func(link vnl.Link) error
	linkDelFn     func(link vnl.Link) error
	linkSetUpFn   func(link vnl.Link) error
	linkSetDownFn func(link vnl.Link) error
	linkSetMTUFn  func(link vnl.Link, mtu int) error
	linkListFn    func() ([]vnl.Link, error)
}

func (m *mockNetlinkOps) LinkByName(name string) (vnl.Link, error) {
	if m.linkByNameFn != nil {
		return m.linkByNameFn(name)
	}
	return nil, errors.New("Link not found")
}

func (m *mockNetlinkOps) LinkAdd(link vnl.Link) error {
	if m.linkAddFn != nil {
		return m.linkAddFn(link)
	}
	return nil
}

func (m *mockNetlinkOps) LinkDel(link vnl.Link) error {
	if m.linkDelFn != nil {
		return m.linkDelFn(link)
	}
	return nil
}

func (m *mockNetlinkOps) LinkSetUp(link vnl.Link) error {
	if m.linkSetUpFn != nil {
		return m.linkSetUpFn(link)
	}
	return nil
}

func (m *mockNetlinkOps) LinkSetDown(link vnl.Link) error {
	if m.linkSetDownFn != nil {
		return m.linkSetDownFn(link)
	}
	return nil
}

func (m *mockNetlinkOps) LinkSetMTU(link vnl.Link, mtu int) error {
	if m.linkSetMTUFn != nil {
		return m.linkSetMTUFn(link, mtu)
	}
	return nil
}

func (m *mockNetlinkOps) LinkList() ([]vnl.Link, error) {
	if m.linkListFn != nil {
		return m.linkListFn()
	}
	return []vnl.Link{}, nil
}

// createDummyLink creates a dummy link for testing
func createDummyLink(name string) vnl.Link {
	return &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:     1,
			Name:      name,
			MTU:       1500,
			Flags:     net.FlagUp | net.FlagBroadcast,
			OperState: vnl.OperUp,
		},
	}
}

// createTuntapLink creates a tuntap link for testing
func createTuntapLink(name string, mode vnl.TuntapMode) *vnl.Tuntap {
	return &vnl.Tuntap{
		LinkAttrs: vnl.LinkAttrs{
			Index:     1,
			Name:      name,
			MTU:       1500,
			Flags:     net.FlagUp | net.FlagBroadcast,
			OperState: vnl.OperUp,
		},
		Mode:       mode,
		Owner:      1000,
		Group:      1000,
		NonPersist: false,
	}
}

// TestGetLink_WithMock tests GetLink with mock
func TestGetLink_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		info, err := m.GetLink("test0")
		require.NoError(t, err)
		assert.Equal(t, "test0", info.Name)
		assert.Equal(t, 1500, info.MTU)
	})

	t.Run("generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("unexpected error")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.GetLink("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})
}

// TestSetLinkUp_WithMock tests SetLinkUp with mock
func TestSetLinkUp_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
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
		err := m.SetLinkUp("test0")
		require.NoError(t, err)
	})

	t.Run("link lookup generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("unexpected error")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.SetLinkUp("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("set up generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
			linkSetUpFn: func(link vnl.Link) error {
				return errors.New("set up failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.SetLinkUp("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeStateFailed, netlinkErr.Type)
	})

	t.Run("set up permission error", func(t *testing.T) {
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
		err := m.SetLinkUp("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
	})
}

// TestSetLinkDown_WithMock tests SetLinkDown with mock
func TestSetLinkDown_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
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
		err := m.SetLinkDown("test0")
		require.NoError(t, err)
	})

	t.Run("link lookup generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("unexpected error")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.SetLinkDown("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("set down generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
			linkSetDownFn: func(link vnl.Link) error {
				return errors.New("set down failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.SetLinkDown("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeStateFailed, netlinkErr.Type)
	})

	t.Run("set down permission error", func(t *testing.T) {
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
		err := m.SetLinkDown("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
	})
}

// TestSetLinkMTU_WithMock tests SetLinkMTU with mock
func TestSetLinkMTU_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
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
		err := m.SetLinkMTU("test0", 9000)
		require.NoError(t, err)
	})

	t.Run("link lookup generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("unexpected error")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.SetLinkMTU("test0", 1500)
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("set MTU generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				return errors.New("set MTU failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.SetLinkMTU("test0", 1500)
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("set MTU permission error", func(t *testing.T) {
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
		err := m.SetLinkMTU("test0", 1500)
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
	})
}

// TestDeleteLink_WithMock tests DeleteLink with mock
func TestDeleteLink_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
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
		err := m.DeleteLink("test0")
		require.NoError(t, err)
	})

	t.Run("link lookup generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("unexpected error")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.DeleteLink("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeDeleteFailed, netlinkErr.Type)
	})

	t.Run("delete generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
			linkDelFn: func(link vnl.Link) error {
				return errors.New("delete failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.DeleteLink("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeDeleteFailed, netlinkErr.Type)
	})

	t.Run("delete permission error", func(t *testing.T) {
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
		err := m.DeleteLink("test0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
	})
}

// TestListLinks_WithMock tests ListLinks with mock
func TestListLinks_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success with links", func(t *testing.T) {
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

// TestCreateTAP_WithMock tests CreateTAP with mock
func TestCreateTAP_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success without MTU", func(t *testing.T) {
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
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
		})
		require.NoError(t, err)
	})

	t.Run("success with MTU", func(t *testing.T) {
		callCount := 0
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				callCount++
				if callCount == 1 {
					// First call during exists check
					return nil, errors.New("Link not found")
				}
				// Second call after creation for MTU setting
				return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
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
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
			MTU:   9000,
		})
		require.NoError(t, err)
	})

	t.Run("already exists at check", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
		})
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeAlreadyExists, netlinkErr.Type)
	})

	t.Run("permission error on add", func(t *testing.T) {
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
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
		})
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypePermission, netlinkErr.Type)
	})

	t.Run("exists error on add", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("Link not found")
			},
			linkAddFn: func(link vnl.Link) error {
				return syscall.EEXIST
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
		})
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeAlreadyExists, netlinkErr.Type)
	})

	t.Run("generic error on add", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("Link not found")
			},
			linkAddFn: func(link vnl.Link) error {
				return errors.New("create failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
		})
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeCreateFailed, netlinkErr.Type)
	})

	t.Run("MTU lookup failure with cleanup", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				// Always return not found to simulate lookup failure after create
				return nil, errors.New("Link not found")
			},
			linkAddFn: func(link vnl.Link) error {
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
			MTU:   9000,
		})
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("MTU set failure with cleanup", func(t *testing.T) {
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
				return errors.New("set MTU failed")
			},
			linkDelFn: func(link vnl.Link) error {
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.CreateTAP(&TAPConfig{
			Name:  "tap0",
			Owner: 1000,
			Group: 1000,
			MTU:   9000,
		})
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

	t.Run("multi-queue enabled", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("Link not found")
			},
			linkAddFn: func(link vnl.Link) error {
				tuntap, ok := link.(*vnl.Tuntap)
				require.True(t, ok)
				// Verify multi-queue flag is set
				assert.True(t, (tuntap.Flags&vnl.TUNTAP_MULTI_QUEUE_DEFAULTS) != 0)
				return nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.CreateTAP(&TAPConfig{
			Name:       "tap0",
			Owner:      1000,
			Group:      1000,
			MultiQueue: true,
		})
		require.NoError(t, err)
	})
}

// TestGetTAP_WithMock tests GetTAP with mock
func TestGetTAP_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createTuntapLink(name, vnl.TUNTAP_MODE_TAP), nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		info, err := m.GetTAP("tap0")
		require.NoError(t, err)
		assert.Equal(t, "tap0", info.Name)
		assert.Equal(t, uint32(1000), info.Owner)
		assert.Equal(t, uint32(1000), info.Group)
	})

	t.Run("generic error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("unexpected error")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		_, err := m.GetTAP("tap0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
	})

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
		_, err := m.GetTAP("tun0")
		require.Error(t, err)

		var netlinkErr *NetlinkError
		require.ErrorAs(t, err, &netlinkErr)
		assert.Equal(t, ErrorTypeSetupFailed, netlinkErr.Type)
		assert.Contains(t, err.Error(), "is TUN")
	})
}

// TestListTAPs_WithMock tests ListTAPs with mock
func TestListTAPs_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success with mixed devices", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkListFn: func() ([]vnl.Link, error) {
				return []vnl.Link{
					createDummyLink("lo"),
					createDummyLink("eth0"),
					createTuntapLink("tap0", vnl.TUNTAP_MODE_TAP),
					createTuntapLink("tun0", vnl.TUNTAP_MODE_TUN),
					createTuntapLink("tap1", vnl.TUNTAP_MODE_TAP),
				}, nil
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		taps, err := m.ListTAPs()
		require.NoError(t, err)
		// Should only have tap0 and tap1
		assert.Len(t, taps, 2)
		for _, tap := range taps {
			assert.Contains(t, []string{"tap0", "tap1"}, tap.Name)
		}
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

	t.Run("empty list", func(t *testing.T) {
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
		taps, err := m.ListTAPs()
		require.NoError(t, err)
		assert.Len(t, taps, 0)
	})
}

// TestDeleteLinkUnsafe_WithMock tests deleteLinkUnsafe with mock
func TestDeleteLinkUnsafe_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	t.Run("success", func(t *testing.T) {
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

	t.Run("lookup error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return nil, errors.New("not found")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.deleteLinkUnsafe("test0")
		require.Error(t, err)
	})

	t.Run("delete error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return createDummyLink(name), nil
			},
			linkDelFn: func(link vnl.Link) error {
				return errors.New("delete failed")
			},
		}
		SetNetlinkOps(mock)

		m := NewManager()
		err := m.deleteLinkUnsafe("test0")
		require.Error(t, err)
	})
}

// TestNetlinkOps_SetAndReset tests SetNetlinkOps and ResetNetlinkOps
func TestNetlinkOps_SetAndReset(t *testing.T) {
	// Save original
	orig := getOps()
	defer ResetNetlinkOps()

	// Set custom ops
	custom := &mockNetlinkOps{}
	SetNetlinkOps(custom)
	assert.Equal(t, custom, getOps())

	// Reset
	ResetNetlinkOps()
	// After reset, ops should be realNetlinkOps (not our custom one)
	assert.NotEqual(t, custom, getOps())
	// And it should work like original
	assert.IsType(t, &realNetlinkOps{}, getOps())
	// Verify original is also realNetlinkOps
	assert.IsType(t, &realNetlinkOps{}, orig)
}

// TestTuntapToTAPInfo_WithMock tests tuntapToTAPInfo
func TestTuntapToTAPInfo_WithMock(t *testing.T) {
	t.Run("with multi-queue flag", func(t *testing.T) {
		tuntap := &vnl.Tuntap{
			LinkAttrs: vnl.LinkAttrs{
				Index:     1,
				Name:      "tap-mq",
				MTU:       1500,
				OperState: vnl.OperUp,
			},
			Mode:       vnl.TUNTAP_MODE_TAP,
			Owner:      1000,
			Group:      1000,
			NonPersist: false,
			Flags:      vnl.TUNTAP_MULTI_QUEUE,
		}

		info := tuntapToTAPInfo(tuntap)
		assert.True(t, info.MultiQueue)
		assert.True(t, info.Persist)
	})

	t.Run("without multi-queue flag", func(t *testing.T) {
		tuntap := &vnl.Tuntap{
			LinkAttrs: vnl.LinkAttrs{
				Index:     1,
				Name:      "tap-nomq",
				MTU:       1500,
				OperState: vnl.OperDown,
			},
			Mode:       vnl.TUNTAP_MODE_TAP,
			Owner:      0,
			Group:      0,
			NonPersist: true,
			Flags:      vnl.TUNTAP_DEFAULTS,
		}

		info := tuntapToTAPInfo(tuntap)
		assert.False(t, info.MultiQueue)
		assert.False(t, info.Persist)
		assert.Equal(t, uint32(0), info.Owner)
		assert.Equal(t, uint32(0), info.Group)
		assert.Equal(t, LinkStateDown, info.OperState)
	})
}

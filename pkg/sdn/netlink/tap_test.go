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
	"strings"
	"syscall"
	"testing"

	vnl "github.com/vishvananda/netlink"
)

func TestManager_CreateTAP_InvalidConfig(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		config  *TAPConfig
		wantErr bool
		errType ErrorType
	}{
		{
			name: "empty name",
			config: &TAPConfig{
				Name:  "",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: true,
			errType: ErrorTypeInvalidName,
		},
		{
			name: "name too long",
			config: &TAPConfig{
				Name:  "verylonginterfacename",
				Owner: 1000,
				Group: 1000,
			},
			wantErr: true,
			errType: ErrorTypeInvalidName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.CreateTAP(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateTAP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				var netlinkErr *NetlinkError
				if ne, ok := err.(*NetlinkError); ok {
					netlinkErr = ne
				}
				if netlinkErr == nil {
					t.Errorf("expected NetlinkError, got %T", err)
					return
				}
				if netlinkErr.Type != tt.errType {
					t.Errorf("Error type = %v, want %v", netlinkErr.Type, tt.errType)
				}
			}
		})
	}
}

func TestManager_CreateTAP_WithoutRoot(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to simulate permission denied
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
		Name:  "tap-test0",
		Owner: 1000,
		Group: 1000,
	}

	err := m.CreateTAP(config)
	if err == nil {
		t.Fatal("CreateTAP() should fail without root privileges")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T: %v", err, err)
	}

	if netlinkErr.Type != ErrorTypePermission {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypePermission)
	}
}

func TestManager_CreateTAPSimple_WithoutRoot(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to simulate permission denied
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

	err := m.CreateTAPSimple("tap-test0", 1000, 1000)
	if err == nil {
		t.Fatal("CreateTAPSimple() should fail without root privileges")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T: %v", err, err)
	}
}

func TestManager_DeleteTAP_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to return not found
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteTAP("tap-nonexistent99999")
	if err == nil {
		t.Fatal("DeleteTAP() should return error for non-existent interface")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeNotFound)
	}
}

func TestManager_GetTAP_InvalidName(t *testing.T) {
	m := NewManager()

	_, err := m.GetTAP("")
	if err == nil {
		t.Fatal("GetTAP() should return error for empty name")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeInvalidName {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeInvalidName)
	}
}

func TestManager_GetTAP_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to return not found
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	_, err := m.GetTAP("tap-nonexistent99999")
	if err == nil {
		t.Fatal("GetTAP() should return error for non-existent interface")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeNotFound)
	}
}

func TestManager_GetTAP_NotTAPDevice(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to return a non-TAP device (dummy)
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

	m := NewManager()

	// Try to get loopback as a TAP device
	_, err := m.GetTAP("lo")
	if err == nil {
		t.Fatal("GetTAP() should return error for non-TAP device")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeSetupFailed {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeSetupFailed)
	}

	if !strings.Contains(err.Error(), "not a TAP device") {
		t.Errorf("Error message should mention 'not a TAP device', got: %v", err)
	}
}

func TestManager_ListTAPs(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to return a list of links
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
	if err != nil {
		t.Fatalf("ListTAPs() failed: %v", err)
	}

	if taps == nil {
		t.Fatal("ListTAPs() returned nil")
	}

	// Should only have tap0
	if len(taps) != 1 {
		t.Errorf("Expected 1 TAP device, got %d", len(taps))
	}
}

func TestManager_SetTAPUp_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to return not found
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetTAPUp("tap-nonexistent99999")
	if err == nil {
		t.Fatal("SetTAPUp() should return error for non-existent interface")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeNotFound)
	}
}

func TestManager_SetTAPDown_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	// Mock the netlink operations to return not found
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetTAPDown("tap-nonexistent99999")
	if err == nil {
		t.Fatal("SetTAPDown() should return error for non-existent interface")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeNotFound)
	}
}

func TestTuntapToTAPInfo(t *testing.T) {
	// Create a mock Tuntap structure to test the conversion function
	tuntap := &vnl.Tuntap{
		LinkAttrs: vnl.LinkAttrs{
			Index:        1,
			Name:         "tap0",
			MTU:          1500,
			Flags:        0x1003,
			HardwareAddr: nil,
			OperState:    vnl.OperUp,
			MasterIndex:  0,
		},
		Mode:       vnl.TUNTAP_MODE_TAP,
		Flags:      vnl.TUNTAP_MULTI_QUEUE,
		Queues:     2,
		Owner:      1000,
		Group:      1000,
		NonPersist: false,
	}

	tapInfo := tuntapToTAPInfo(tuntap)

	if tapInfo == nil {
		t.Fatal("tuntapToTAPInfo() returned nil")
	}

	if tapInfo.Name != "tap0" {
		t.Errorf("Name = %s, want tap0", tapInfo.Name)
	}

	if tapInfo.Index != 1 {
		t.Errorf("Index = %d, want 1", tapInfo.Index)
	}

	if tapInfo.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", tapInfo.MTU)
	}

	if tapInfo.Owner != 1000 {
		t.Errorf("Owner = %d, want 1000", tapInfo.Owner)
	}

	if tapInfo.Group != 1000 {
		t.Errorf("Group = %d, want 1000", tapInfo.Group)
	}

	if !tapInfo.MultiQueue {
		t.Error("MultiQueue = false, want true")
	}

	if !tapInfo.Persist {
		t.Error("Persist = false, want true (NonPersist was false)")
	}

	if tapInfo.OperState != LinkStateUp {
		t.Errorf("OperState = %v, want %v", tapInfo.OperState, LinkStateUp)
	}
}

func TestTuntapToTAPInfo_NonMultiQueue(t *testing.T) {
	// Test with multi-queue disabled
	tuntap := &vnl.Tuntap{
		LinkAttrs: vnl.LinkAttrs{
			Index:     2,
			Name:      "tap1",
			MTU:       1400,
			OperState: vnl.OperDown,
		},
		Mode:       vnl.TUNTAP_MODE_TAP,
		Flags:      0, // No multi-queue flag
		Owner:      0,
		Group:      0,
		NonPersist: true, // Non-persistent
	}

	tapInfo := tuntapToTAPInfo(tuntap)

	if tapInfo == nil {
		t.Fatal("tuntapToTAPInfo() returned nil")
	}

	if tapInfo.MultiQueue {
		t.Error("MultiQueue = true, want false")
	}

	if tapInfo.Persist {
		t.Error("Persist = true, want false (NonPersist was true)")
	}

	if tapInfo.OperState != LinkStateDown {
		t.Errorf("OperState = %v, want %v", tapInfo.OperState, LinkStateDown)
	}
}

func TestTuntapToTAPInfo_UnknownState(t *testing.T) {
	// Test with unknown operational state
	tuntap := &vnl.Tuntap{
		LinkAttrs: vnl.LinkAttrs{
			Index:     3,
			Name:      "tap2",
			OperState: vnl.OperUnknown,
		},
		Mode: vnl.TUNTAP_MODE_TAP,
	}

	tapInfo := tuntapToTAPInfo(tuntap)

	if tapInfo == nil {
		t.Fatal("tuntapToTAPInfo() returned nil")
	}

	if tapInfo.OperState != LinkStateUnknown {
		t.Errorf("OperState = %v, want %v", tapInfo.OperState, LinkStateUnknown)
	}
}

// TestManager_TAPLifecycle_WithMock tests full TAP lifecycle using mocks
func TestManager_TAPLifecycle_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-test0"
	var created bool
	var linkUp bool

	// Mock the netlink operations
	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500,
					Flags: func() net.Flags {
						if linkUp {
							return net.FlagUp
						} else {
							return 0
						}
					}(),
					OperState: func() vnl.LinkOperState {
						if linkUp {
							return vnl.OperUp
						} else {
							return vnl.OperDown
						}
					}(),
				},
				Mode:       vnl.TUNTAP_MODE_TAP,
				Owner:      1000,
				Group:      1000,
				NonPersist: false,
			}, nil
		},
		linkAddFn: func(link vnl.Link) error {
			created = true
			return nil
		},
		linkDelFn: func(link vnl.Link) error {
			created = false
			return nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			linkUp = true
			return nil
		},
		linkSetDownFn: func(link vnl.Link) error {
			linkUp = false
			return nil
		},
		linkListFn: func() ([]vnl.Link, error) {
			if created {
				return []vnl.Link{
					&vnl.Tuntap{
						LinkAttrs: vnl.LinkAttrs{Name: tapName},
						Mode:      vnl.TUNTAP_MODE_TAP,
						Owner:     1000,
						Group:     1000,
					},
				}, nil
			}
			return []vnl.Link{}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Create TAP device
	config := &TAPConfig{
		Name:       tapName,
		Owner:      1000,
		Group:      1000,
		MultiQueue: false,
		Persist:    true,
		MTU:        0, // No MTU setting to simplify test
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() failed: %v", err)
	}

	// Verify creation
	tapInfo, err := m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() failed: %v", err)
	}

	if tapInfo.Name != tapName {
		t.Errorf("Name = %s, want %s", tapInfo.Name, tapName)
	}

	// Bring interface up
	err = m.SetTAPUp(tapName)
	if err != nil {
		t.Fatalf("SetTAPUp() failed: %v", err)
	}

	// Verify it's up
	tapInfo, err = m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() after SetTAPUp failed: %v", err)
	}

	if !IsUp(tapInfo.Flags) {
		t.Error("Interface should be up after SetTAPUp()")
	}

	// Bring interface down
	err = m.SetTAPDown(tapName)
	if err != nil {
		t.Fatalf("SetTAPDown() failed: %v", err)
	}

	// Verify it's down
	tapInfo, err = m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() after SetTAPDown failed: %v", err)
	}

	if IsUp(tapInfo.Flags) {
		t.Error("Interface should be down after SetTAPDown()")
	}

	// Test listing TAPs
	taps, err := m.ListTAPs()
	if err != nil {
		t.Fatalf("ListTAPs() failed: %v", err)
	}

	found := false
	for _, tap := range taps {
		if tap.Name == tapName {
			found = true
			break
		}
	}

	if !found {
		t.Error("Created TAP device not found in ListTAPs()")
	}

	// Delete the interface
	err = m.DeleteTAP(tapName)
	if err != nil {
		t.Fatalf("DeleteTAP() failed: %v", err)
	}

	// Verify deletion
	_, err = m.GetTAP(tapName)
	if err == nil {
		t.Fatal("GetTAP() should fail after deletion")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Error type after deletion = %v, want %v",
			netlinkErr.Type, ErrorTypeNotFound)
	}
}

// TestManager_CreateTAPSimple_WithMock tests simple creation with mocks
func TestManager_CreateTAPSimple_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-simple0"
	var created bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
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
		linkAddFn: func(link vnl.Link) error {
			created = true
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Create TAP device using simple method
	err := m.CreateTAPSimple(tapName, 1000, 1000)
	if err != nil {
		t.Fatalf("CreateTAPSimple() failed: %v", err)
	}

	// Verify creation
	tapInfo, err := m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() failed: %v", err)
	}

	if tapInfo.Name != tapName {
		t.Errorf("Name = %s, want %s", tapInfo.Name, tapName)
	}
}

// TestManager_CreateTAP_AlreadyExists tests duplicate creation with mocks
func TestManager_CreateTAP_AlreadyExists(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-dup0"

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Name: name,
				},
				Mode: vnl.TUNTAP_MODE_TAP,
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:  tapName,
		Owner: 1000,
		Group: 1000,
	}

	// Try to create - should fail because it already exists
	err := m.CreateTAP(config)
	if err == nil {
		t.Fatal("CreateTAP() should fail when interface already exists")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeAlreadyExists {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeAlreadyExists)
	}
}

// TestManager_CreateTAP_WithMultiQueue tests multi-queue creation with mocks
func TestManager_CreateTAP_WithMultiQueue(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-mq0"

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			if !ok {
				t.Error("Expected Tuntap link type")
				return nil
			}
			// Verify multi-queue flag is set
			if (tuntap.Flags & vnl.TUNTAP_MULTI_QUEUE_DEFAULTS) == 0 {
				t.Error("Multi-queue flag not set")
			}
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:       tapName,
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() with multi-queue failed: %v", err)
	}
}

// TestManager_CreateTAP_WithCustomMTU tests TAP creation with custom MTU using mocks
func TestManager_CreateTAP_WithCustomMTU(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-mtu0"
	var created bool
	var mtuSet int

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   mtuSet,
				},
				Mode:  vnl.TUNTAP_MODE_TAP,
				Owner: 1000,
				Group: 1000,
			}, nil
		},
		linkAddFn: func(link vnl.Link) error {
			created = true
			return nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			mtuSet = mtu
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    tapName,
		Owner:   1000,
		Group:   1000,
		MTU:     9000, // Jumbo frames
		Persist: true,
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() with custom MTU failed: %v", err)
	}

	// Verify MTU was set
	tapInfo, err := m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() failed: %v", err)
	}

	if tapInfo.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", tapInfo.MTU)
	}
}

// TestManager_CreateTAP_WithPersist tests persistent TAP creation with mocks
func TestManager_CreateTAP_WithPersist(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-persist0"
	var created bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500,
				},
				Mode:       vnl.TUNTAP_MODE_TAP,
				Owner:      1000,
				Group:      1000,
				NonPersist: false,
			}, nil
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			if ok && !tuntap.NonPersist {
				// Verify persist is set
				created = true
			}
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    tapName,
		Owner:   1000,
		Group:   1000,
		Persist: true,
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() with persist failed: %v", err)
	}

	// Verify creation
	tapInfo, err := m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() failed: %v", err)
	}

	if tapInfo.Name != tapName {
		t.Errorf("Name = %s, want %s", tapInfo.Name, tapName)
	}
}

// TestDeleteLinkUnsafe_Coverage ensures deleteLinkUnsafe is covered with mocks
func TestDeleteLinkUnsafe_TAPCoverage(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-unsafe0"
	var created bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
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
			created = true
			return nil
		},
		linkDelFn: func(link vnl.Link) error {
			created = false
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Create a TAP device first
	config := &TAPConfig{
		Name:  tapName,
		Owner: 1000,
		Group: 1000,
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() failed: %v", err)
	}

	// Test deleteLinkUnsafe via DeleteTAP
	err = m.DeleteTAP(tapName)
	if err != nil {
		t.Fatalf("DeleteTAP() failed: %v", err)
	}

	// Verify deletion
	_, err = m.GetTAP(tapName)
	if err == nil {
		t.Fatal("GetTAP() should fail after deletion")
	}
}

// Test CreateTAP with zero MTU (should use default) with mocks
func TestManager_CreateTAP_DefaultMTU(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-def-mtu"
	var created bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500, // Default MTU
				},
				Mode:  vnl.TUNTAP_MODE_TAP,
				Owner: 1000,
				Group: 1000,
			}, nil
		},
		linkAddFn: func(link vnl.Link) error {
			created = true
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    tapName,
		Owner:   1000,
		Group:   1000,
		MTU:     0, // Should use default
		Persist: true,
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() with default MTU failed: %v", err)
	}

	// Verify creation
	tapInfo, err := m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() failed: %v", err)
	}

	// Should have default MTU (usually 1500)
	if tapInfo.MTU <= 0 {
		t.Errorf("MTU should be > 0, got %d", tapInfo.MTU)
	}
}

// Test GetTAP with TUN device (should fail) using mocks
func TestManager_GetTAP_TUNDevice(t *testing.T) {
	defer ResetNetlinkOps()

	tunName := "tun-test0"

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
				},
				Mode:  vnl.TUNTAP_MODE_TUN, // TUN not TAP
				Owner: 1000,
				Group: 1000,
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Try to get it as a TAP device - should fail
	_, err := m.GetTAP(tunName)
	if err == nil {
		t.Fatal("GetTAP() should fail for TUN device")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T", err)
	}

	if netlinkErr.Type != ErrorTypeSetupFailed {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeSetupFailed)
	}

	if !strings.Contains(err.Error(), "TUN") {
		t.Errorf("Error should mention TUN device, got: %v", err)
	}
}

// Test Link operations (up/down) on TAP device with mocks
func TestManager_TAPLinkUpDown_WithMock(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-updown"
	var created bool
	var linkUp bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
				return nil, errors.New("Link not found")
			}
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
		linkAddFn: func(link vnl.Link) error {
			created = true
			return nil
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

	m := NewManager()

	config := &TAPConfig{
		Name:    tapName,
		Owner:   1000,
		Group:   1000,
		Persist: true,
	}

	// Create TAP
	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() failed: %v", err)
	}

	// Bring it up
	err = m.SetLinkUp(tapName)
	if err != nil {
		t.Fatalf("SetLinkUp() failed: %v", err)
	}

	// Verify it's up
	info, err := m.GetLink(tapName)
	if err != nil {
		t.Fatalf("GetLink() failed: %v", err)
	}
	if !IsUp(info.Flags) {
		t.Error("Link should be up")
	}

	// Bring it down
	err = m.SetLinkDown(tapName)
	if err != nil {
		t.Fatalf("SetLinkDown() failed: %v", err)
	}

	// Verify it's down
	info, err = m.GetLink(tapName)
	if err != nil {
		t.Fatalf("GetLink() failed: %v", err)
	}
	if IsUp(info.Flags) {
		t.Error("Link should be down")
	}
}

// Test CreateTAP with invalid MTU that fails after device creation (cleanup path)
func TestManager_CreateTAP_InvalidMTUAfterCreate(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-badmtu"
	callCount := 0
	var cleaned bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			callCount++
			if callCount == 1 {
				// First call during exists check
				return nil, errors.New("Link not found")
			}
			// Second call after creation for MTU setting
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
			return errors.New("invalid MTU")
		},
		linkDelFn: func(link vnl.Link) error {
			cleaned = true
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:    tapName,
		Owner:   1000,
		Group:   1000,
		MTU:     100000, // Invalid MTU
		Persist: true,
	}

	err := m.CreateTAP(config)
	// Should fail at MTU setting
	if err == nil {
		t.Fatal("CreateTAP() should fail with invalid MTU")
	}

	// Verify cleanup was called
	if !cleaned {
		t.Error("Device should have been cleaned up after MTU failure")
	}
}

// TestManager_DeleteLinkUnsafe_NotFound tests deleteLinkUnsafe with non-existent interface
func TestManager_DeleteLinkUnsafe_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Test deleteLinkUnsafe directly with a non-existent interface
	// This will exercise the error path where LinkByName fails
	err := m.deleteLinkUnsafe("nonexistent-tap-12345")
	if err == nil {
		t.Error("deleteLinkUnsafe() should return error for non-existent interface")
	}
}

// TestManager_CreateTAP_MultiQueueWithPersist tests multi-queue with persist flag using mocks
func TestManager_CreateTAP_MultiQueueWithPersist(t *testing.T) {
	defer ResetNetlinkOps()

	tapName := "tap-mq-persist"
	var created bool

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if !created {
				return nil, errors.New("Link not found")
			}
			return &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  name,
					MTU:   1500,
				},
				Mode:       vnl.TUNTAP_MODE_TAP,
				Flags:      vnl.TUNTAP_MULTI_QUEUE,
				Owner:      1000,
				Group:      1000,
				NonPersist: false,
			}, nil
		},
		linkAddFn: func(link vnl.Link) error {
			tuntap, ok := link.(*vnl.Tuntap)
			if !ok {
				t.Error("Expected Tuntap link type")
				return nil
			}
			// Verify multi-queue flag is set
			if (tuntap.Flags & vnl.TUNTAP_MULTI_QUEUE_DEFAULTS) == 0 {
				t.Error("Multi-queue flag not set")
			}
			// Verify persist is set
			if tuntap.NonPersist {
				t.Error("NonPersist should be false for persist=true")
			}
			created = true
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	config := &TAPConfig{
		Name:       tapName,
		Owner:      1000,
		Group:      1000,
		MultiQueue: true,
		Persist:    true,
	}

	err := m.CreateTAP(config)
	if err != nil {
		t.Fatalf("CreateTAP() with multi-queue and persist failed: %v", err)
	}

	// Verify creation
	tapInfo, err := m.GetTAP(tapName)
	if err != nil {
		t.Fatalf("GetTAP() failed: %v", err)
	}

	if !tapInfo.MultiQueue {
		t.Error("MultiQueue should be true")
	}

	if !tapInfo.Persist {
		t.Error("Persist should be true")
	}
}

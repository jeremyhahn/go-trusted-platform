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
	"testing"

	"github.com/vishvananda/netlink"
)

// TestLinkToInfo_EdgeCases tests linkToInfo with various edge cases
func TestLinkToInfo_EdgeCases(t *testing.T) {
	// Test with different operational states
	tests := []struct {
		name      string
		operState netlink.LinkOperState
		want      LinkState
	}{
		{"OperUp", netlink.OperUp, LinkStateUp},
		{"OperDown", netlink.OperDown, LinkStateDown},
		{"OperUnknown", netlink.OperUnknown, LinkStateUnknown},
		{"OperNotPresent", netlink.OperNotPresent, LinkStateUnknown},
		{"OperLowerLayerDown", netlink.OperLowerLayerDown, LinkStateUnknown},
		{"OperTesting", netlink.OperTesting, LinkStateUnknown},
		{"OperDormant", netlink.OperDormant, LinkStateUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a dummy link structure with the operstate
			dummy := &netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Index:     1,
					Name:      "test0",
					OperState: tt.operState,
				},
			}

			info := linkToInfo(dummy)
			if info.OperState != tt.want {
				t.Errorf("linkToInfo() OperState = %v, want %v", info.OperState, tt.want)
			}
		})
	}
}

func TestLinkToInfo_HardwareAddrVariants(t *testing.T) {
	// Test with various hardware address scenarios
	tests := []struct {
		name   string
		hwAddr net.HardwareAddr
		want   string
	}{
		{
			name:   "valid MAC",
			hwAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			want:   "00:11:22:33:44:55",
		},
		{
			name:   "nil hardware addr",
			hwAddr: nil,
			want:   "",
		},
		{
			name:   "empty hardware addr",
			hwAddr: net.HardwareAddr{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dummy := &netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Index:        1,
					Name:         "test0",
					HardwareAddr: tt.hwAddr,
					OperState:    netlink.OperUp,
				},
			}

			info := linkToInfo(dummy)
			if info.HardwareAddr != tt.want {
				t.Errorf("linkToInfo() HardwareAddr = %v, want %v", info.HardwareAddr, tt.want)
			}
		})
	}
}

func TestLinkInfo_AllFields(t *testing.T) {
	// Test that all fields are properly extracted
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Index:        42,
			Name:         "dummy0",
			Flags:        net.FlagUp | net.FlagBroadcast | net.FlagRunning,
			MTU:          9000,
			HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			OperState:    netlink.OperUp,
			MasterIndex:  10,
		},
	}

	info := linkToInfo(dummy)

	if info.Index != 42 {
		t.Errorf("Index = %d, want 42", info.Index)
	}
	if info.Name != "dummy0" {
		t.Errorf("Name = %s, want dummy0", info.Name)
	}
	if info.Type != "dummy" {
		t.Errorf("Type = %s, want dummy", info.Type)
	}
	if info.Flags != uint32(net.FlagUp|net.FlagBroadcast|net.FlagRunning) {
		t.Errorf("Flags = %d, want %d", info.Flags, uint32(net.FlagUp|net.FlagBroadcast|net.FlagRunning))
	}
	if info.MTU != 9000 {
		t.Errorf("MTU = %d, want 9000", info.MTU)
	}
	if info.HardwareAddr != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("HardwareAddr = %s, want aa:bb:cc:dd:ee:ff", info.HardwareAddr)
	}
	if info.OperState != LinkStateUp {
		t.Errorf("OperState = %v, want %v", info.OperState, LinkStateUp)
	}
	if info.Master != 10 {
		t.Errorf("Master = %d, want 10", info.Master)
	}
}

func TestIsNotFoundError_StringMatch(t *testing.T) {
	// Test the string matching for "Link not found"
	err := errors.New("Link not found")
	if !isNotFoundError(err) {
		t.Error("isNotFoundError() should return true for 'Link not found' error")
	}
}

func TestTAPConfig_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		config  *TAPConfig
		wantErr bool
	}{
		{
			name: "exactly 15 chars",
			config: &TAPConfig{
				Name: "123456789012345",
			},
			wantErr: false,
		},
		{
			name: "exactly 16 chars",
			config: &TAPConfig{
				Name: "1234567890123456",
			},
			wantErr: true,
		},
		{
			name: "single char",
			config: &TAPConfig{
				Name: "a",
			},
			wantErr: false,
		},
		{
			name: "with all options",
			config: &TAPConfig{
				Name:       "tap0",
				Owner:      1000,
				Group:      1000,
				MultiQueue: true,
				Persist:    true,
				MTU:        9000,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestManager_MultipleInstances(t *testing.T) {
	// Test that multiple managers can coexist
	m1 := NewManager()
	m2 := NewManager()

	if m1 == nil || m2 == nil {
		t.Fatal("NewManager() returned nil")
	}

	// They should be independent instances
	if m1 == m2 {
		t.Error("Multiple NewManager() calls should return different instances")
	}

	// Both should work independently
	_, err1 := m1.GetLink("lo")
	_, err2 := m2.GetLink("lo")

	if err1 != nil {
		t.Errorf("m1.GetLink() failed: %v", err1)
	}
	if err2 != nil {
		t.Errorf("m2.GetLink() failed: %v", err2)
	}
}

func TestTAPInfo_EmbeddedFields(t *testing.T) {
	// Verify that TAPInfo properly embeds LinkInfo and all fields are accessible
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
		Persist:    false,
	}

	// Test embedded field access
	if tapInfo.Index != 1 {
		t.Errorf("Index = %d, want 1", tapInfo.Index)
	}
	if tapInfo.Name != "tap0" {
		t.Errorf("Name = %s, want tap0", tapInfo.Name)
	}
	if tapInfo.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", tapInfo.MTU)
	}
	if tapInfo.Owner != 1000 {
		t.Errorf("Owner = %d, want 1000", tapInfo.Owner)
	}
}

func TestIsFlagSet_MultipleFlags(t *testing.T) {
	// Test with multiple flags set
	flags := uint32(net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning)

	if !IsFlagSet(flags, net.FlagUp) {
		t.Error("FlagUp should be set")
	}
	if !IsFlagSet(flags, net.FlagBroadcast) {
		t.Error("FlagBroadcast should be set")
	}
	if !IsFlagSet(flags, net.FlagMulticast) {
		t.Error("FlagMulticast should be set")
	}
	if !IsFlagSet(flags, net.FlagRunning) {
		t.Error("FlagRunning should be set")
	}
	if IsFlagSet(flags, net.FlagLoopback) {
		t.Error("FlagLoopback should not be set")
	}
	if IsFlagSet(flags, net.FlagPointToPoint) {
		t.Error("FlagPointToPoint should not be set")
	}
}

func TestManager_GetLink_DifferentTypes(t *testing.T) {
	m := NewManager()

	// Test getting loopback (different type than TAP)
	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) failed: %v", err)
	}

	// Loopback should have specific characteristics
	if info.Type != "device" {
		t.Logf("Loopback type = %s (informational)", info.Type)
	}

	// Verify it has valid fields
	if info.Index <= 0 {
		t.Errorf("Index should be > 0, got %d", info.Index)
	}
	if info.Name == "" {
		t.Error("Name should not be empty")
	}
}

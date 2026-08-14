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
	"net"
	"os"
	"testing"

	vnl "github.com/vishvananda/netlink"
)

// TestSetLinkUp_AllBranches tests SetLinkUp exercising all reachable branches
// Without root: exercises invalid name, not found, and permission error paths
// With root: additionally exercises success path
func TestSetLinkUp_AllBranches(t *testing.T) {
	m := NewManager()

	// Always run: invalid name (covered)
	t.Run("empty name", func(t *testing.T) {
		err := m.SetLinkUp("")
		if err == nil {
			t.Error("expected error for empty name")
		}
		assertErrorTypeHelper(t, err, ErrorTypeInvalidName)
	})

	// Always run: not found (covered)
	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.SetLinkUp("nonexistent-if-9999")
		if err == nil {
			t.Error("expected error for nonexistent interface")
		}
		assertErrorTypeHelper(t, err, ErrorTypeNotFound)
	})

	// Test with loopback - behavior depends on privileges
	t.Run("loopback interface", func(t *testing.T) {
		err := m.SetLinkUp("lo")
		if os.Geteuid() == 0 {
			// As root: should succeed (covers success path line 78)
			if err != nil {
				t.Errorf("SetLinkUp(lo) failed as root: %v", err)
			}
		} else {
			// As non-root: should get permission error (already covered)
			if err == nil {
				t.Error("expected permission error as non-root")
			}
			assertErrorTypeHelper(t, err, ErrorTypePermission)
		}
	})
}

// TestSetLinkDown_AllBranches tests SetLinkDown exercising all reachable branches
func TestSetLinkDown_AllBranches(t *testing.T) {
	m := NewManager()

	t.Run("empty name", func(t *testing.T) {
		err := m.SetLinkDown("")
		if err == nil {
			t.Error("expected error for empty name")
		}
		assertErrorTypeHelper(t, err, ErrorTypeInvalidName)
	})

	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.SetLinkDown("nonexistent-if-8888")
		if err == nil {
			t.Error("expected error for nonexistent interface")
		}
		assertErrorTypeHelper(t, err, ErrorTypeNotFound)
	})

	// As non-root with loopback: permission error
	// As root: success path (line 105)
	t.Run("loopback interface", func(t *testing.T) {
		err := m.SetLinkDown("lo")
		if os.Geteuid() == 0 {
			// As root: should succeed
			if err != nil {
				t.Errorf("SetLinkDown(lo) failed as root: %v", err)
			}
			// Bring it back up for other tests
			if restoreErr := m.SetLinkUp("lo"); restoreErr != nil {
				t.Logf("Warning: failed to restore loopback: %v", restoreErr)
			}
		} else {
			// As non-root: permission error
			if err == nil {
				t.Error("expected permission error as non-root")
			}
			assertErrorTypeHelper(t, err, ErrorTypePermission)
		}
	})
}

// TestSetLinkMTU_AllBranches tests SetLinkMTU exercising all reachable branches
func TestSetLinkMTU_AllBranches(t *testing.T) {
	m := NewManager()

	t.Run("empty name", func(t *testing.T) {
		err := m.SetLinkMTU("", 1500)
		if err == nil {
			t.Error("expected error for empty name")
		}
		assertErrorTypeHelper(t, err, ErrorTypeInvalidName)
	})

	t.Run("mtu too small", func(t *testing.T) {
		err := m.SetLinkMTU("lo", 67)
		if err == nil {
			t.Error("expected error for MTU too small")
		}
		assertErrorTypeHelper(t, err, ErrorTypeSetupFailed)
	})

	t.Run("mtu too large", func(t *testing.T) {
		err := m.SetLinkMTU("lo", 65537)
		if err == nil {
			t.Error("expected error for MTU too large")
		}
		assertErrorTypeHelper(t, err, ErrorTypeSetupFailed)
	})

	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.SetLinkMTU("nonexistent-if-7777", 1500)
		if err == nil {
			t.Error("expected error for nonexistent interface")
		}
		assertErrorTypeHelper(t, err, ErrorTypeNotFound)
	})

	// With root: exercises success path (line 136)
	// Without root: exercises permission error
	t.Run("loopback interface", func(t *testing.T) {
		// Get current MTU to restore later
		info, infoErr := m.GetLink("lo")
		if infoErr != nil {
			t.Fatalf("GetLink(lo) failed: %v", infoErr)
		}
		origMTU := info.MTU

		// Try to set MTU
		err := m.SetLinkMTU("lo", 65535)
		if os.Geteuid() == 0 {
			// As root: should succeed
			if err != nil {
				t.Errorf("SetLinkMTU(lo) failed as root: %v", err)
			} else {
				// Restore original MTU
				if restoreErr := m.SetLinkMTU("lo", origMTU); restoreErr != nil {
					t.Logf("Warning: failed to restore loopback MTU: %v", restoreErr)
				}
			}
		} else {
			// As non-root: permission error
			if err == nil {
				t.Error("expected permission error as non-root")
			}
			assertErrorTypeHelper(t, err, ErrorTypePermission)
		}
	})
}

// TestDeleteLink_AllBranches tests DeleteLink exercising all reachable branches
func TestDeleteLink_AllBranches(t *testing.T) {
	m := NewManager()

	t.Run("empty name", func(t *testing.T) {
		err := m.DeleteLink("")
		if err == nil {
			t.Error("expected error for empty name")
		}
		assertErrorTypeHelper(t, err, ErrorTypeInvalidName)
	})

	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.DeleteLink("nonexistent-if-6666")
		if err == nil {
			t.Error("expected error for nonexistent interface")
		}
		assertErrorTypeHelper(t, err, ErrorTypeNotFound)
	})

	// Cannot test successful delete without root AND a deletable interface
	// Loopback cannot be deleted, so we test the permission path
	t.Run("loopback interface", func(t *testing.T) {
		err := m.DeleteLink("lo")
		if err == nil {
			t.Error("expected error when deleting loopback")
		}
		// Without root: permission error
		// With root: still fails (loopback is special, cannot be deleted)
		// Either way, we get an error - covers the error branch
		if os.Geteuid() != 0 {
			assertErrorTypeHelper(t, err, ErrorTypePermission)
		}
	})
}

// TestCreateTAP_SuccessPathCoverage tests CreateTAP success path when running as root
func TestCreateTAP_SuccessPathCoverage(t *testing.T) {
	m := NewManager()
	tapName := "tap-cov-test"

	// Clean up any existing device
	_ = m.DeleteLink(tapName)

	config := &TAPConfig{
		Name:    tapName,
		Owner:   uint32(os.Getuid()),
		Group:   uint32(os.Getgid()),
		Persist: true,
	}

	err := m.CreateTAP(config)
	if os.Geteuid() == 0 {
		// As root: should succeed (covers lines 30-32, 55-81)
		if err != nil {
			t.Fatalf("CreateTAP failed as root: %v", err)
		}
		// Verify it was created
		tapInfo, getErr := m.GetTAP(tapName)
		if getErr != nil {
			t.Fatalf("GetTAP failed: %v", getErr)
		}
		if tapInfo.Name != tapName {
			t.Errorf("name = %s, want %s", tapInfo.Name, tapName)
		}
		// Clean up
		if delErr := m.DeleteLink(tapName); delErr != nil {
			t.Logf("Warning: cleanup failed: %v", delErr)
		}
	} else {
		// As non-root: should get permission or create failed error
		if err == nil {
			t.Error("expected error as non-root")
		}
		assertErrorTypeAnyHelper(t, err, ErrorTypePermission, ErrorTypeCreateFailed)
	}
}

// TestCreateTAP_WithMTUCoverage tests CreateTAP with custom MTU
func TestCreateTAP_WithMTUCoverage(t *testing.T) {
	m := NewManager()
	tapName := "tap-mtu-cov"

	// Clean up any existing device
	_ = m.DeleteLink(tapName)

	config := &TAPConfig{
		Name:    tapName,
		Owner:   uint32(os.Getuid()),
		Group:   uint32(os.Getgid()),
		MTU:     9000, // Jumbo frames
		Persist: true,
	}

	err := m.CreateTAP(config)
	if os.Geteuid() == 0 {
		// As root: should succeed (covers MTU setting path lines 66-81)
		if err != nil {
			t.Fatalf("CreateTAP with MTU failed as root: %v", err)
		}
		// Verify MTU was set
		tapInfo, getErr := m.GetTAP(tapName)
		if getErr != nil {
			t.Fatalf("GetTAP failed: %v", getErr)
		}
		if tapInfo.MTU != 9000 {
			t.Errorf("MTU = %d, want 9000", tapInfo.MTU)
		}
		// Clean up
		if delErr := m.DeleteLink(tapName); delErr != nil {
			t.Logf("Warning: cleanup failed: %v", delErr)
		}
	} else if err == nil {
		// As non-root: should get permission or create failed error
		t.Error("expected error as non-root")
	}
}

// TestCreateTAP_WithMultiQueueCoverage tests CreateTAP with multi-queue enabled
func TestCreateTAP_WithMultiQueueCoverage(t *testing.T) {
	m := NewManager()
	tapName := "tap-mq-cov"

	// Clean up any existing device
	_ = m.DeleteLink(tapName)

	config := &TAPConfig{
		Name:       tapName,
		Owner:      uint32(os.Getuid()),
		Group:      uint32(os.Getgid()),
		MultiQueue: true,
		Persist:    true,
	}

	err := m.CreateTAP(config)
	if os.Geteuid() == 0 {
		// As root: should succeed (covers multi-queue path lines 49-52)
		if err != nil {
			t.Fatalf("CreateTAP with multi-queue failed as root: %v", err)
		}
		// Clean up
		if delErr := m.DeleteLink(tapName); delErr != nil {
			t.Logf("Warning: cleanup failed: %v", delErr)
		}
	} else if err == nil {
		// As non-root: should get permission or create failed error
		t.Error("expected error as non-root")
	}
}

// TestListTAPs_WithDevicesCoverage tests ListTAPs when TAP devices exist
func TestListTAPs_WithDevicesCoverage(t *testing.T) {
	m := NewManager()
	tapName := "tap-list-cov"

	// Clean up any existing device
	_ = m.DeleteLink(tapName)

	// First, list without any TAP we created
	taps1, err := m.ListTAPs()
	if err != nil {
		t.Fatalf("ListTAPs failed: %v", err)
	}
	initialCount := len(taps1)

	if os.Geteuid() == 0 {
		// Create a TAP device to list
		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}
		createErr := m.CreateTAP(config)
		if createErr != nil {
			t.Fatalf("CreateTAP failed: %v", createErr)
		}
		defer func() {
			_ = m.DeleteLink(tapName)
		}()

		// List again - should include our TAP (covers iteration lines 144-150)
		taps2, listErr := m.ListTAPs()
		if listErr != nil {
			t.Fatalf("ListTAPs after create failed: %v", listErr)
		}
		if len(taps2) != initialCount+1 {
			t.Errorf("TAP count = %d, want %d", len(taps2), initialCount+1)
		}
		// Find our TAP
		found := false
		for _, tap := range taps2 {
			if tap.Name == tapName {
				found = true
				break
			}
		}
		if !found {
			t.Error("created TAP not found in list")
		}
	}
}

// TestGetTAP_WithTUNDeviceCoverage tests GetTAP returns error for TUN device
func TestGetTAP_WithTUNDeviceCoverage(t *testing.T) {
	if os.Geteuid() != 0 {
		// Without root, test the "not a TAP" path using loopback
		m := NewManager()
		_, err := m.GetTAP("lo")
		if err == nil {
			t.Error("expected error for non-TAP device")
		}
		assertErrorTypeHelper(t, err, ErrorTypeSetupFailed)
		return
	}

	// With root, create an actual TUN device to test the TUN check (line 127)
	m := NewManager()
	tunName := "tun-cov-test"

	// Create a TUN device
	tun := &vnl.Tuntap{
		LinkAttrs: vnl.LinkAttrs{
			Name: tunName,
		},
		Mode:       vnl.TUNTAP_MODE_TUN,
		Flags:      vnl.TUNTAP_DEFAULTS,
		Owner:      uint32(os.Getuid()),
		Group:      uint32(os.Getgid()),
		NonPersist: false,
	}

	addErr := vnl.LinkAdd(tun)
	if addErr != nil {
		t.Fatalf("failed to create TUN device: %v", addErr)
	}
	defer func() {
		link, _ := vnl.LinkByName(tunName)
		if link != nil {
			_ = vnl.LinkDel(link)
		}
	}()

	// Try to get it as TAP - should fail with "is TUN" error (covers line 127)
	_, err := m.GetTAP(tunName)
	if err == nil {
		t.Error("expected error for TUN device")
	}
	assertErrorTypeHelper(t, err, ErrorTypeSetupFailed)
	if errStr := err.Error(); errStr == "" {
		t.Error("error message is empty")
	}
}

// TestDeleteLinkUnsafe_ErrorPathCoverage tests deleteLinkUnsafe error handling
func TestDeleteLinkUnsafe_ErrorPathCoverage(t *testing.T) {
	m := NewManager()
	// This exercises the error path where LinkByName fails (line 185-186)
	err := m.deleteLinkUnsafe("nonexistent-tap-cov-xyz")
	if err == nil {
		t.Error("expected error for nonexistent interface")
	}
}

// TestDeleteLinkUnsafe_SuccessPathCoverage tests deleteLinkUnsafe success path
func TestDeleteLinkUnsafe_SuccessPathCoverage(t *testing.T) {
	if os.Geteuid() != 0 {
		// Without root, just verify the method exists and handles errors
		m := NewManager()
		err := m.deleteLinkUnsafe("nonexistent-cov-99")
		if err == nil {
			t.Error("expected error")
		}
		return
	}

	// With root, create and delete a TAP to exercise success path (line 188)
	m := NewManager()
	tapName := "tap-unsafe-cov"

	// Create TAP
	config := &TAPConfig{
		Name:    tapName,
		Owner:   uint32(os.Getuid()),
		Group:   uint32(os.Getgid()),
		Persist: true,
	}
	if err := m.CreateTAP(config); err != nil {
		t.Fatalf("CreateTAP failed: %v", err)
	}

	// Delete using deleteLinkUnsafe
	err := m.deleteLinkUnsafe(tapName)
	if err != nil {
		t.Errorf("deleteLinkUnsafe failed: %v", err)
	}

	// Verify deletion
	_, getErr := m.GetLink(tapName)
	if getErr == nil {
		t.Error("interface should be deleted")
	}
}

// TestLinkToInfo_AllOperStatesCoverage tests linkToInfo with all operational states
func TestLinkToInfo_AllOperStatesCoverage(t *testing.T) {
	tests := []struct {
		name      string
		operState vnl.LinkOperState
		want      LinkState
	}{
		{"OperUp", vnl.OperUp, LinkStateUp},
		{"OperDown", vnl.OperDown, LinkStateDown},
		{"OperUnknown", vnl.OperUnknown, LinkStateUnknown},
		{"OperNotPresent", vnl.OperNotPresent, LinkStateUnknown},
		{"OperLowerLayerDown", vnl.OperLowerLayerDown, LinkStateUnknown},
		{"OperTesting", vnl.OperTesting, LinkStateUnknown},
		{"OperDormant", vnl.OperDormant, LinkStateUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     1,
					Name:      "test",
					OperState: tt.operState,
				},
			}
			info := linkToInfo(link)
			if info.OperState != tt.want {
				t.Errorf("OperState = %v, want %v", info.OperState, tt.want)
			}
		})
	}
}

// TestLinkToInfo_HardwareAddrCoverage tests linkToInfo hardware address handling
func TestLinkToInfo_HardwareAddrCoverage(t *testing.T) {
	tests := []struct {
		name   string
		hwAddr net.HardwareAddr
		want   string
	}{
		{"nil", nil, ""},
		{"empty", net.HardwareAddr{}, ""},
		{"valid MAC", net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "aa:bb:cc:dd:ee:ff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:        1,
					Name:         "test",
					HardwareAddr: tt.hwAddr,
				},
			}
			info := linkToInfo(link)
			if info.HardwareAddr != tt.want {
				t.Errorf("HardwareAddr = %q, want %q", info.HardwareAddr, tt.want)
			}
		})
	}
}

// TestTuntapToTAPInfo_AllCombinationsCoverage tests tuntapToTAPInfo with various configurations
func TestTuntapToTAPInfo_AllCombinationsCoverage(t *testing.T) {
	tests := []struct {
		name        string
		flags       vnl.TuntapFlag
		nonPersist  bool
		wantMQ      bool
		wantPersist bool
	}{
		{
			name:        "default flags, persist",
			flags:       vnl.TUNTAP_DEFAULTS,
			nonPersist:  false,
			wantMQ:      false,
			wantPersist: true,
		},
		{
			name:        "multi-queue enabled, non-persist",
			flags:       vnl.TUNTAP_MULTI_QUEUE,
			nonPersist:  true,
			wantMQ:      true,
			wantPersist: false,
		},
		{
			name:        "multi-queue defaults, persist",
			flags:       vnl.TUNTAP_MULTI_QUEUE_DEFAULTS,
			nonPersist:  false,
			wantMQ:      true,
			wantPersist: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tuntap := &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index:     1,
					Name:      "tap0",
					OperState: vnl.OperUp,
				},
				Mode:       vnl.TUNTAP_MODE_TAP,
				Flags:      tt.flags,
				Owner:      1000,
				Group:      1000,
				NonPersist: tt.nonPersist,
			}

			info := tuntapToTAPInfo(tuntap)
			if info == nil {
				t.Fatal("returned nil")
			}
			if info.MultiQueue != tt.wantMQ {
				t.Errorf("MultiQueue = %v, want %v", info.MultiQueue, tt.wantMQ)
			}
			if info.Persist != tt.wantPersist {
				t.Errorf("Persist = %v, want %v", info.Persist, tt.wantPersist)
			}
			if info.Owner != 1000 {
				t.Errorf("Owner = %d, want 1000", info.Owner)
			}
			if info.Group != 1000 {
				t.Errorf("Group = %d, want 1000", info.Group)
			}
		})
	}
}

// Helper function to assert error type (named to avoid conflict with other test files)
func assertErrorTypeHelper(t *testing.T, err error, expected ErrorType) {
	t.Helper()
	if err == nil {
		t.Error("expected error, got nil")
		return
	}
	netlinkErr, ok := err.(*NetlinkError)
	if !ok {
		t.Errorf("expected *NetlinkError, got %T", err)
		return
	}
	if netlinkErr.Type != expected {
		t.Errorf("error type = %v, want %v", netlinkErr.Type, expected)
	}
}

// Helper function to assert error type is one of several
func assertErrorTypeAnyHelper(t *testing.T, err error, expected ...ErrorType) {
	t.Helper()
	if err == nil {
		t.Error("expected error, got nil")
		return
	}
	netlinkErr, ok := err.(*NetlinkError)
	if !ok {
		t.Errorf("expected *NetlinkError, got %T", err)
		return
	}
	for _, exp := range expected {
		if netlinkErr.Type == exp {
			return
		}
	}
	t.Errorf("error type = %v, want one of %v", netlinkErr.Type, expected)
}

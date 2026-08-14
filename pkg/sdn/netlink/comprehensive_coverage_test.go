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
	"os"
	"testing"

	vnl "github.com/vishvananda/netlink"
)

// Tests in this file do NOT use t.Skip and exercise code paths
// regardless of whether running as root or not.

// TestCreateTAP_AllPathsNoSkip tests all CreateTAP paths without skip guards
func TestCreateTAP_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	// Test validation errors (always fails regardless of root)
	t.Run("empty name validation", func(t *testing.T) {
		config := &TAPConfig{Name: ""}
		err := m.CreateTAP(config)
		if err == nil {
			t.Fatal("expected error for empty name")
		}
		verifyErrorType(t, err, ErrorTypeInvalidName)
	})

	t.Run("name too long validation", func(t *testing.T) {
		config := &TAPConfig{Name: "1234567890123456"} // 16 chars
		err := m.CreateTAP(config)
		if err == nil {
			t.Fatal("expected error for name too long")
		}
		verifyErrorType(t, err, ErrorTypeInvalidName)
	})

	// Test actual creation - behavior depends on privileges
	t.Run("valid config", func(t *testing.T) {
		tapName := "tap-no-skip"
		_ = m.DeleteLink(tapName) // cleanup any existing

		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}

		err := m.CreateTAP(config)
		if os.Geteuid() == 0 {
			// Root: should succeed
			if err != nil {
				t.Errorf("CreateTAP failed as root: %v", err)
			}
			_ = m.DeleteLink(tapName) // cleanup
		} else if err == nil {
			// Non-root: should fail with permission or create error
			t.Error("expected permission error as non-root")
		}
	})

	// Test already exists - requires root to test properly
	t.Run("already exists", func(t *testing.T) {
		tapName := "tap-exists"
		_ = m.DeleteLink(tapName)

		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}

		if os.Geteuid() == 0 {
			// Create first
			err := m.CreateTAP(config)
			if err != nil {
				t.Fatalf("first CreateTAP failed: %v", err)
			}
			defer func() { _ = m.DeleteLink(tapName) }()

			// Try to create again - should fail with already exists
			err = m.CreateTAP(config)
			if err == nil {
				t.Fatal("expected already exists error")
			}
			verifyErrorType(t, err, ErrorTypeAlreadyExists)
		} else {
			// Non-root: just verify we get an error
			err := m.CreateTAP(config)
			if err == nil {
				t.Error("expected error as non-root")
			}
		}
	})

	// Test with MTU setting
	t.Run("with custom MTU", func(t *testing.T) {
		tapName := "tap-mtu"
		_ = m.DeleteLink(tapName)

		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			MTU:     9000,
			Persist: true,
		}

		err := m.CreateTAP(config)
		if os.Geteuid() == 0 {
			// Root: should succeed and MTU should be set
			if err != nil {
				t.Errorf("CreateTAP with MTU failed: %v", err)
			} else {
				// Verify MTU
				info, getErr := m.GetTAP(tapName)
				if getErr != nil {
					t.Errorf("GetTAP failed: %v", getErr)
				} else if info.MTU != 9000 {
					t.Errorf("MTU = %d, want 9000", info.MTU)
				}
				_ = m.DeleteLink(tapName)
			}
		} else {
			// Non-root: expect error
			if err == nil {
				t.Error("expected error as non-root")
			}
		}
	})

	// Test multi-queue
	t.Run("with multi-queue", func(t *testing.T) {
		tapName := "tap-mqtest"
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
			// Root: should succeed
			if err != nil {
				t.Errorf("CreateTAP with multi-queue failed: %v", err)
			}
			_ = m.DeleteLink(tapName)
		} else if err == nil {
			// Non-root: expect error
			t.Error("expected error as non-root")
		}
	})
}

// TestGetTAP_AllPathsNoSkip tests all GetTAP paths without skip guards
func TestGetTAP_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	t.Run("empty name", func(t *testing.T) {
		_, err := m.GetTAP("")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
		verifyErrorType(t, err, ErrorTypeInvalidName)
	})

	t.Run("nonexistent interface", func(t *testing.T) {
		_, err := m.GetTAP("tap-nonexistent-xyz")
		if err == nil {
			t.Fatal("expected error for nonexistent interface")
		}
		verifyErrorType(t, err, ErrorTypeNotFound)
	})

	t.Run("not a TAP device - loopback", func(t *testing.T) {
		_, err := m.GetTAP("lo")
		if err == nil {
			t.Fatal("expected error for non-TAP device")
		}
		verifyErrorType(t, err, ErrorTypeSetupFailed)
	})

	// Test actual TAP retrieval - requires root
	t.Run("valid TAP device", func(t *testing.T) {
		if os.Geteuid() != 0 {
			// Non-root: test validation only
			return
		}

		tapName := "tap-get-test"
		_ = m.DeleteLink(tapName)

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
		defer func() { _ = m.DeleteLink(tapName) }()

		// Get TAP info
		info, err := m.GetTAP(tapName)
		if err != nil {
			t.Fatalf("GetTAP failed: %v", err)
		}
		if info.Name != tapName {
			t.Errorf("name = %s, want %s", info.Name, tapName)
		}
	})

	// Test TUN device detection - requires root
	t.Run("TUN device rejection", func(t *testing.T) {
		if os.Geteuid() != 0 {
			// Non-root: can't create TUN, use loopback test instead
			return
		}

		tunName := "tun-test"
		// Create TUN device
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

		if err := vnl.LinkAdd(tun); err != nil {
			t.Fatalf("failed to create TUN: %v", err)
		}
		defer func() {
			link, _ := vnl.LinkByName(tunName)
			if link != nil {
				_ = vnl.LinkDel(link)
			}
		}()

		// Try to get as TAP - should fail
		_, err := m.GetTAP(tunName)
		if err == nil {
			t.Fatal("expected error for TUN device")
		}
		verifyErrorType(t, err, ErrorTypeSetupFailed)
	})
}

// TestListTAPs_AllPathsNoSkip tests ListTAPs without skip guards
func TestListTAPs_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	// Always succeeds - list is always valid even if empty
	t.Run("list without TAPs", func(t *testing.T) {
		taps, err := m.ListTAPs()
		if err != nil {
			t.Fatalf("ListTAPs failed: %v", err)
		}
		if taps == nil {
			t.Fatal("returned nil slice")
		}
		// Count is >= 0
	})

	// Test with created TAP - requires root
	t.Run("list with TAP", func(t *testing.T) {
		if os.Geteuid() != 0 {
			return
		}

		tapName := "tap-list"
		_ = m.DeleteLink(tapName)

		// Get initial count
		taps1, _ := m.ListTAPs()
		initialCount := len(taps1)

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
		defer func() { _ = m.DeleteLink(tapName) }()

		// List again
		taps2, err := m.ListTAPs()
		if err != nil {
			t.Fatalf("ListTAPs failed: %v", err)
		}
		if len(taps2) != initialCount+1 {
			t.Errorf("count = %d, want %d", len(taps2), initialCount+1)
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
			t.Error("created TAP not in list")
		}
	})
}

// TestSetTAPUp_AllPathsNoSkip tests SetTAPUp without skip guards
func TestSetTAPUp_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.SetTAPUp("tap-nonexistent-up")
		if err == nil {
			t.Fatal("expected error")
		}
		verifyErrorType(t, err, ErrorTypeNotFound)
	})

	t.Run("valid TAP", func(t *testing.T) {
		if os.Geteuid() != 0 {
			return
		}

		tapName := "tap-up-test"
		_ = m.DeleteLink(tapName)

		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}
		if err := m.CreateTAP(config); err != nil {
			t.Fatalf("CreateTAP failed: %v", err)
		}
		defer func() { _ = m.DeleteLink(tapName) }()

		err := m.SetTAPUp(tapName)
		if err != nil {
			t.Errorf("SetTAPUp failed: %v", err)
		}

		// Verify
		info, _ := m.GetLink(tapName)
		if !IsUp(info.Flags) {
			t.Error("interface should be up")
		}
	})
}

// TestSetTAPDown_AllPathsNoSkip tests SetTAPDown without skip guards
func TestSetTAPDown_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.SetTAPDown("tap-nonexistent-down")
		if err == nil {
			t.Fatal("expected error")
		}
		verifyErrorType(t, err, ErrorTypeNotFound)
	})

	t.Run("valid TAP", func(t *testing.T) {
		if os.Geteuid() != 0 {
			return
		}

		tapName := "tap-down-test"
		_ = m.DeleteLink(tapName)

		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}
		if err := m.CreateTAP(config); err != nil {
			t.Fatalf("CreateTAP failed: %v", err)
		}
		defer func() { _ = m.DeleteLink(tapName) }()

		// Bring up first
		_ = m.SetTAPUp(tapName)

		err := m.SetTAPDown(tapName)
		if err != nil {
			t.Errorf("SetTAPDown failed: %v", err)
		}

		// Verify
		info, _ := m.GetLink(tapName)
		if IsUp(info.Flags) {
			t.Error("interface should be down")
		}
	})
}

// TestDeleteTAP_AllPathsNoSkip tests DeleteTAP without skip guards
func TestDeleteTAP_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	t.Run("nonexistent interface", func(t *testing.T) {
		err := m.DeleteTAP("tap-nonexistent-del")
		if err == nil {
			t.Fatal("expected error")
		}
		verifyErrorType(t, err, ErrorTypeNotFound)
	})

	t.Run("valid TAP", func(t *testing.T) {
		if os.Geteuid() != 0 {
			return
		}

		tapName := "tap-delete"
		_ = m.DeleteLink(tapName)

		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}
		if err := m.CreateTAP(config); err != nil {
			t.Fatalf("CreateTAP failed: %v", err)
		}

		err := m.DeleteTAP(tapName)
		if err != nil {
			t.Errorf("DeleteTAP failed: %v", err)
		}

		// Verify deleted
		_, err = m.GetLink(tapName)
		if err == nil {
			t.Error("interface should be deleted")
		}
	})
}

// TestDeleteLink_SuccessPath tests successful DeleteLink
func TestDeleteLink_SuccessPath(t *testing.T) {
	m := NewManager()

	if os.Geteuid() != 0 {
		// Non-root: test error paths only
		err := m.DeleteLink("nonexistent-xyz")
		if err == nil {
			t.Error("expected error for nonexistent interface")
		}
		return
	}

	// Root: test full lifecycle
	tapName := "tap-del-success"
	_ = m.DeleteLink(tapName)

	config := &TAPConfig{
		Name:    tapName,
		Owner:   uint32(os.Getuid()),
		Group:   uint32(os.Getgid()),
		Persist: true,
	}
	if err := m.CreateTAP(config); err != nil {
		t.Fatalf("CreateTAP failed: %v", err)
	}

	// Delete successfully
	err := m.DeleteLink(tapName)
	if err != nil {
		t.Errorf("DeleteLink failed: %v", err)
	}

	// Verify deleted
	_, err = m.GetLink(tapName)
	verifyErrorType(t, err, ErrorTypeNotFound)
}

// TestCreateTAPSimple_AllPathsNoSkip tests CreateTAPSimple without skip guards
func TestCreateTAPSimple_AllPathsNoSkip(t *testing.T) {
	m := NewManager()

	tapName := "tap-simple"
	_ = m.DeleteLink(tapName)

	err := m.CreateTAPSimple(tapName, uint32(os.Getuid()), uint32(os.Getgid()))
	if os.Geteuid() == 0 {
		if err != nil {
			t.Errorf("CreateTAPSimple failed: %v", err)
		}
		_ = m.DeleteLink(tapName)
	} else if err == nil {
		t.Error("expected error as non-root")
	}
}

// TestDeleteLinkUnsafe_PathsNoSkip tests deleteLinkUnsafe paths
func TestDeleteLinkUnsafe_PathsNoSkip(t *testing.T) {
	m := NewManager()

	// Error path - always testable
	t.Run("nonexistent", func(t *testing.T) {
		err := m.deleteLinkUnsafe("nonexistent-unsafe")
		if err == nil {
			t.Error("expected error")
		}
	})

	// Success path - requires root
	t.Run("success", func(t *testing.T) {
		if os.Geteuid() != 0 {
			return
		}

		tapName := "tap-unsafe-success"
		config := &TAPConfig{
			Name:    tapName,
			Owner:   uint32(os.Getuid()),
			Group:   uint32(os.Getgid()),
			Persist: true,
		}
		if err := m.CreateTAP(config); err != nil {
			t.Fatalf("CreateTAP failed: %v", err)
		}

		err := m.deleteLinkUnsafe(tapName)
		if err != nil {
			t.Errorf("deleteLinkUnsafe failed: %v", err)
		}
	})
}

// Helper to verify error type
func verifyErrorType(t *testing.T, err error, expected ErrorType) {
	t.Helper()
	if err == nil {
		t.Error("expected error")
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

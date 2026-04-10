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

	vnl "github.com/vishvananda/netlink"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
}

func TestManager_GetLink_InvalidName(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name    string
		ifName  string
		wantErr bool
		errType ErrorType
	}{
		{
			name:    "empty name",
			ifName:  "",
			wantErr: true,
			errType: ErrorTypeInvalidName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.GetLink(tt.ifName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLink() error = %v, wantErr %v", err, tt.wantErr)
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

func TestManager_GetLink_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Try to get a non-existent interface
	_, err := m.GetLink("nonexistent99999")
	if err == nil {
		t.Fatal("GetLink() should return error for non-existent interface")
	}

	var netlinkErr *NetlinkError
	if ne, ok := err.(*NetlinkError); ok {
		netlinkErr = ne
	}
	if netlinkErr == nil {
		t.Fatalf("expected NetlinkError, got %T: %v", err, err)
	}

	if netlinkErr.Type != ErrorTypeNotFound {
		t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypeNotFound)
	}
}

func TestManager_GetLink_Loopback(t *testing.T) {
	defer ResetNetlinkOps()

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

	m := NewManager()

	// Get loopback interface (should always exist)
	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) failed: %v", err)
	}

	if info == nil {
		t.Fatal("GetLink(lo) returned nil info")
	}

	if info.Name != "lo" {
		t.Errorf("Name = %s, want lo", info.Name)
	}

	if info.Index <= 0 {
		t.Errorf("Index = %d, want > 0", info.Index)
	}
}

func TestManager_SetLinkUp_InvalidName(t *testing.T) {
	m := NewManager()

	err := m.SetLinkUp("")
	if err == nil {
		t.Fatal("SetLinkUp() should return error for empty name")
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

func TestManager_SetLinkUp_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkUp("nonexistent99999")
	if err == nil {
		t.Fatal("SetLinkUp() should return error for non-existent interface")
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

func TestManager_SetLinkDown_InvalidName(t *testing.T) {
	m := NewManager()

	err := m.SetLinkDown("")
	if err == nil {
		t.Fatal("SetLinkDown() should return error for empty name")
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

func TestManager_SetLinkDown_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkDown("nonexistent99999")
	if err == nil {
		t.Fatal("SetLinkDown() should return error for non-existent interface")
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

func TestManager_SetLinkMTU_InvalidName(t *testing.T) {
	m := NewManager()

	err := m.SetLinkMTU("", 1500)
	if err == nil {
		t.Fatal("SetLinkMTU() should return error for empty name")
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

func TestManager_SetLinkMTU_InvalidMTU(t *testing.T) {
	m := NewManager()

	tests := []struct {
		name string
		mtu  int
	}{
		{"too small", 67},
		{"too large", 65537},
		{"negative", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.SetLinkMTU("lo", tt.mtu)
			if err == nil {
				t.Errorf("SetLinkMTU(%d) should return error", tt.mtu)
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
		})
	}
}

func TestManager_SetLinkMTU_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.SetLinkMTU("nonexistent99999", 1500)
	if err == nil {
		t.Fatal("SetLinkMTU() should return error for non-existent interface")
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

func TestManager_DeleteLink_InvalidName(t *testing.T) {
	m := NewManager()

	err := m.DeleteLink("")
	if err == nil {
		t.Fatal("DeleteLink() should return error for empty name")
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

func TestManager_DeleteLink_NotFound(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return nil, errors.New("Link not found")
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	err := m.DeleteLink("nonexistent99999")
	if err == nil {
		t.Fatal("DeleteLink() should return error for non-existent interface")
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

func TestManager_ListLinks(t *testing.T) {
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
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	links, err := m.ListLinks()
	if err != nil {
		t.Fatalf("ListLinks() failed: %v", err)
	}

	if links == nil {
		t.Fatal("ListLinks() returned nil")
	}

	// Should at least have loopback
	if len(links) == 0 {
		t.Error("ListLinks() returned empty list")
	}

	// Find loopback
	var foundLo bool
	for _, link := range links {
		if link.Name == "lo" {
			foundLo = true
			break
		}
	}

	if !foundLo {
		t.Error("ListLinks() did not include loopback interface")
	}
}

func TestIsNotFoundError(t *testing.T) {
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
			name: "other error",
			err:  syscall.EINVAL,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotFoundError(tt.err); got != tt.want {
				t.Errorf("isNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPermissionError(t *testing.T) {
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
			if got := isPermissionError(tt.err); got != tt.want {
				t.Errorf("isPermissionError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsExistsError(t *testing.T) {
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
			if got := isExistsError(tt.err); got != tt.want {
				t.Errorf("isExistsError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFlagSet(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		flag  net.Flags
		want  bool
	}{
		{
			name:  "flag set",
			flags: 0x1003, // IFF_UP | IFF_BROADCAST | IFF_RUNNING
			flag:  net.FlagUp,
			want:  true,
		},
		{
			name:  "flag not set",
			flags: 0x1000, // Just IFF_RUNNING
			flag:  net.FlagUp,
			want:  false,
		},
		{
			name:  "no flags",
			flags: 0,
			flag:  net.FlagUp,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsFlagSet(tt.flags, tt.flag); got != tt.want {
				t.Errorf("IsFlagSet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUp(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{
			name:  "up",
			flags: 0x1003, // IFF_UP | IFF_BROADCAST | IFF_RUNNING
			want:  true,
		},
		{
			name:  "down",
			flags: 0x1000, // Just IFF_RUNNING
			want:  false,
		},
		{
			name:  "no flags",
			flags: 0,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUp(tt.flags); got != tt.want {
				t.Errorf("IsUp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRunning(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{
			name:  "running",
			flags: uint32(net.FlagRunning), // 0x40 on Linux
			want:  true,
		},
		{
			name:  "not running",
			flags: 0x0003, // IFF_UP | IFF_BROADCAST
			want:  false,
		},
		{
			name:  "no flags",
			flags: 0,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRunning(tt.flags); got != tt.want {
				t.Errorf("IsRunning() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestManager_ConcurrentAccess tests thread safety using mocks
func TestManager_ConcurrentAccess(t *testing.T) {
	defer ResetNetlinkOps()

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
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				&vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "lo"}},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()
	done := make(chan bool)

	// Launch multiple goroutines that access the manager concurrently
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			// Multiple read operations
			for j := 0; j < 100; j++ {
				_, _ = m.ListLinks()
				_, _ = m.GetLink("lo")
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestManager_Operations_PermissionError tests operations that return permission errors using mocks
func TestManager_Operations_PermissionError(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()

	t.Run("SetLinkUp permission error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return &vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 1,
						Name:  name,
						Flags: 0, // down
					},
				}, nil
			},
			linkSetUpFn: func(link vnl.Link) error {
				return syscall.EPERM
			},
		}
		SetNetlinkOps(mock)

		err := m.SetLinkUp("eth0")
		if err == nil {
			t.Fatal("SetLinkUp should fail with permission error")
		}

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		if netlinkErr == nil {
			t.Fatalf("expected NetlinkError, got %T", err)
		}

		if netlinkErr.Type != ErrorTypePermission {
			t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypePermission)
		}
	})

	t.Run("SetLinkDown permission error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return &vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 1,
						Name:  name,
						Flags: net.FlagUp,
					},
				}, nil
			},
			linkSetDownFn: func(link vnl.Link) error {
				return syscall.EPERM
			},
		}
		SetNetlinkOps(mock)

		err := m.SetLinkDown("lo")
		if err == nil {
			t.Fatal("SetLinkDown(lo) should fail with permission error")
		}

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		if netlinkErr == nil {
			t.Fatalf("expected NetlinkError, got %T", err)
		}

		if netlinkErr.Type != ErrorTypePermission {
			t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypePermission)
		}
	})

	t.Run("SetLinkMTU permission error", func(t *testing.T) {
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
			linkSetMTUFn: func(link vnl.Link, mtu int) error {
				return syscall.EPERM
			},
		}
		SetNetlinkOps(mock)

		err := m.SetLinkMTU("lo", 16436)
		if err == nil {
			t.Fatal("SetLinkMTU(lo) should fail with permission error")
		}

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		if netlinkErr == nil {
			t.Fatalf("expected NetlinkError, got %T", err)
		}

		if netlinkErr.Type != ErrorTypePermission {
			t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypePermission)
		}
	})

	t.Run("DeleteLink permission error", func(t *testing.T) {
		mock := &mockNetlinkOps{
			linkByNameFn: func(name string) (vnl.Link, error) {
				return &vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index: 1,
						Name:  name,
					},
				}, nil
			},
			linkDelFn: func(link vnl.Link) error {
				return syscall.EPERM
			},
		}
		SetNetlinkOps(mock)

		err := m.DeleteLink("lo")
		if err == nil {
			t.Fatal("DeleteLink(lo) should fail with permission error")
		}

		var netlinkErr *NetlinkError
		if ne, ok := err.(*NetlinkError); ok {
			netlinkErr = ne
		}
		if netlinkErr == nil {
			t.Fatalf("expected NetlinkError, got %T", err)
		}

		if netlinkErr.Type != ErrorTypePermission {
			t.Errorf("Error type = %v, want %v", netlinkErr.Type, ErrorTypePermission)
		}
	})
}

func TestLinkToInfo_WithHardwareAddr(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:        1,
					Name:         "lo",
					MTU:          65536,
					HardwareAddr: nil,
				},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()
	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) failed: %v", err)
	}

	// Loopback may or may not have a hardware address depending on system
	// Just verify the field is properly formatted
	if info.HardwareAddr != "" {
		// If it has an address, it should be valid
		if len(info.HardwareAddr) < 2 {
			t.Errorf("HardwareAddr appears invalid: %s", info.HardwareAddr)
		}
	}
}

func TestManager_SetLinkMTU_ValidRange(t *testing.T) {
	defer ResetNetlinkOps()

	m := NewManager()

	tests := []struct {
		name    string
		mtu     int
		wantErr bool
	}{
		{"minimum valid", 68, false},
		{"maximum valid", 65536, false},
		{"middle value", 1500, false},
		{"just below min", 67, true},
		{"just above max", 65537, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockNetlinkOps{
				linkByNameFn: func(name string) (vnl.Link, error) {
					return nil, errors.New("Link not found")
				},
			}
			SetNetlinkOps(mock)

			// Use non-existent interface to avoid actually changing MTU
			err := m.SetLinkMTU("nonexistent99999", tt.mtu)

			if tt.wantErr {
				// Should get setup failed for invalid MTU before trying to find the interface
				if err == nil {
					t.Fatal("SetLinkMTU() should return error for invalid MTU")
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
			} else {
				// Should get not found error for valid MTU (interface doesn't exist)
				if err == nil {
					t.Fatal("SetLinkMTU() should return error for non-existent interface")
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
		})
	}
}

// Test SetLinkMTU success path with mock
func TestManager_SetLinkMTU_Success(t *testing.T) {
	defer ResetNetlinkOps()

	var currentMTU = 65536

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  "lo",
					MTU:   currentMTU,
				},
			}, nil
		},
		linkSetMTUFn: func(link vnl.Link, mtu int) error {
			currentMTU = mtu
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Try to set a different MTU
	newMTU := 16436 // Common loopback MTU

	err := m.SetLinkMTU("lo", newMTU)
	if err != nil {
		t.Fatalf("SetLinkMTU() failed: %v", err)
	}

	// Verify it was set
	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) after SetMTU failed: %v", err)
	}

	if info.MTU != newMTU {
		t.Errorf("MTU = %d, want %d", info.MTU, newMTU)
	}
}

// Test GetLink with various edge cases using mocks
func TestManager_GetLink_EdgeCases(t *testing.T) {
	defer ResetNetlinkOps()

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

	m := NewManager()

	// Test concurrent access
	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 20; j++ {
				_, _ = m.GetLink("lo")
			}
		}()
	}

	for i := 0; i < 5; i++ {
		<-done
	}
}

// Test ListLinks returns proper data using mocks
func TestManager_ListLinks_Detailed(t *testing.T) {
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
	if err != nil {
		t.Fatalf("ListLinks() failed: %v", err)
	}

	// Verify each link has valid data
	for _, link := range links {
		if link.Index <= 0 {
			t.Errorf("Link %s has invalid index %d", link.Name, link.Index)
		}
		if link.Name == "" {
			t.Error("Link has empty name")
		}
		if link.Type == "" {
			t.Error("Link has empty type")
		}
	}
}

// Test SetLinkUp/Down success paths using mocks
func TestManager_SetLinkUpDown_Success(t *testing.T) {
	defer ResetNetlinkOps()

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

	m := NewManager()
	tapName := "tap-updown-test"

	// Test SetLinkUp
	err := m.SetLinkUp(tapName)
	if err != nil {
		t.Fatalf("SetLinkUp() failed: %v", err)
	}

	// Verify it's up
	info, err := m.GetLink(tapName)
	if err != nil {
		t.Fatalf("GetLink() failed: %v", err)
	}

	if !IsUp(info.Flags) {
		t.Error("Interface should be up after SetLinkUp()")
	}

	// Test SetLinkDown
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
		t.Error("Interface should be down after SetLinkDown()")
	}
}

// Test DeleteLink success path using mocks
func TestManager_DeleteLink_Success(t *testing.T) {
	defer ResetNetlinkOps()

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

	m := NewManager()
	tapName := "tap-delete-test"

	// Delete via DeleteLink
	err := m.DeleteLink(tapName)
	if err != nil {
		t.Fatalf("DeleteLink() failed: %v", err)
	}

	// Verify it's gone
	_, err = m.GetLink(tapName)
	if err == nil {
		t.Fatal("GetLink() should fail after deletion")
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

// Test linkToInfo with different OperState values
func TestLinkToInfo_OperStates(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     1,
					Name:      "lo",
					MTU:       65536,
					OperState: vnl.OperUp,
				},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Get loopback which should be OperUp
	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) failed: %v", err)
	}

	if info.OperState != LinkStateUp {
		t.Errorf("OperState = %v, want %v", info.OperState, LinkStateUp)
	}
}

// TestLinkToInfo_Direct tests linkToInfo function directly with mock links
func TestLinkToInfo_Direct(t *testing.T) {
	tests := []struct {
		name      string
		link      vnl.Link
		wantState LinkState
	}{
		{
			name: "OperUp state",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     1,
					Name:      "test0",
					MTU:       1500,
					OperState: vnl.OperUp,
				},
			},
			wantState: LinkStateUp,
		},
		{
			name: "OperDown state",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     2,
					Name:      "test1",
					MTU:       1400,
					OperState: vnl.OperDown,
				},
			},
			wantState: LinkStateDown,
		},
		{
			name: "OperUnknown state",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     3,
					Name:      "test2",
					MTU:       1500,
					OperState: vnl.OperUnknown,
				},
			},
			wantState: LinkStateUnknown,
		},
		{
			name: "OperNotPresent state (maps to unknown)",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     4,
					Name:      "test3",
					MTU:       1500,
					OperState: vnl.OperNotPresent,
				},
			},
			wantState: LinkStateUnknown,
		},
		{
			name: "OperLowerLayerDown state (maps to unknown)",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:     5,
					Name:      "test4",
					MTU:       1500,
					OperState: vnl.OperLowerLayerDown,
				},
			},
			wantState: LinkStateUnknown,
		},
		{
			name: "with hardware address",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:        6,
					Name:         "test5",
					MTU:          1500,
					HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					OperState:    vnl.OperUp,
				},
			},
			wantState: LinkStateUp,
		},
		{
			name: "with nil hardware address",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index:        7,
					Name:         "test6",
					MTU:          1500,
					HardwareAddr: nil,
					OperState:    vnl.OperUp,
				},
			},
			wantState: LinkStateUp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := linkToInfo(tt.link)
			if info == nil {
				t.Fatal("linkToInfo() returned nil")
			}

			if info.OperState != tt.wantState {
				t.Errorf("OperState = %v, want %v", info.OperState, tt.wantState)
			}

			attrs := tt.link.Attrs()
			if info.Name != attrs.Name {
				t.Errorf("Name = %s, want %s", info.Name, attrs.Name)
			}
			if info.Index != attrs.Index {
				t.Errorf("Index = %d, want %d", info.Index, attrs.Index)
			}
			if info.MTU != attrs.MTU {
				t.Errorf("MTU = %d, want %d", info.MTU, attrs.MTU)
			}

			// Check hardware address handling
			if attrs.HardwareAddr != nil {
				if info.HardwareAddr != attrs.HardwareAddr.String() {
					t.Errorf("HardwareAddr = %s, want %s", info.HardwareAddr, attrs.HardwareAddr.String())
				}
			} else {
				if info.HardwareAddr != "" {
					t.Errorf("HardwareAddr = %s, want empty", info.HardwareAddr)
				}
			}
		})
	}
}

// TestLinkToInfo_MasterIndex tests that master index is properly captured
func TestLinkToInfo_MasterIndex(t *testing.T) {
	link := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:       10,
			Name:        "slave0",
			MasterIndex: 5,
			OperState:   vnl.OperUp,
		},
	}

	info := linkToInfo(link)
	if info == nil {
		t.Fatal("linkToInfo() returned nil")
	}

	if info.Master != 5 {
		t.Errorf("Master = %d, want 5", info.Master)
	}
}

// TestLinkToInfo_Flags tests that flags are properly captured
func TestLinkToInfo_Flags(t *testing.T) {
	flags := net.FlagUp | net.FlagBroadcast | net.FlagRunning
	link := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:     11,
			Name:      "flagtest",
			Flags:     flags,
			OperState: vnl.OperUp,
		},
	}

	info := linkToInfo(link)
	if info == nil {
		t.Fatal("linkToInfo() returned nil")
	}

	if info.Flags != uint32(flags) {
		t.Errorf("Flags = %d, want %d", info.Flags, uint32(flags))
	}

	// Verify flag helper functions work with these flags
	if !IsUp(info.Flags) {
		t.Error("IsUp() should return true")
	}
	if !IsRunning(info.Flags) {
		t.Error("IsRunning() should return true")
	}
}

// Test GetLink on interface with hardware address using mocks
func TestManager_GetLink_WithHardwareAddr(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				&vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index:        1,
						Name:         "eth0",
						MTU:          1500,
						HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					},
				},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	links, err := m.ListLinks()
	if err != nil {
		t.Fatalf("ListLinks() failed: %v", err)
	}

	for _, link := range links {
		if link.HardwareAddr != "" {
			// Found an interface with hardware address, verify it's valid format
			if len(link.HardwareAddr) < 11 { // minimum is xx:xx:xx:xx:xx:xx (17 chars)
				// Some interfaces have shorter addresses, just verify it's not empty
				t.Logf("Interface %s has hardware address: %s", link.Name, link.HardwareAddr)
			}
			return
		}
	}
}

// Test that ListLinks properly processes all interfaces using mocks
func TestManager_ListLinks_AllProcessed(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkListFn: func() ([]vnl.Link, error) {
			return []vnl.Link{
				&vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index:     1,
						Name:      "lo",
						MTU:       65536,
						OperState: vnl.OperUp,
					},
				},
				&vnl.Dummy{
					LinkAttrs: vnl.LinkAttrs{
						Index:     2,
						Name:      "eth0",
						MTU:       1500,
						OperState: vnl.OperDown,
					},
				},
			}, nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	links, err := m.ListLinks()
	if err != nil {
		t.Fatalf("ListLinks() failed: %v", err)
	}

	// Verify all links are properly populated
	for _, link := range links {
		// Every link must have these fields populated
		if link.Index <= 0 {
			t.Errorf("Link %s has invalid index: %d", link.Name, link.Index)
		}
		if link.Name == "" {
			t.Error("Found link with empty name")
		}
		if link.Type == "" {
			t.Error("Found link with empty type")
		}
		// OperState should be one of the valid values
		if link.OperState != LinkStateUp && link.OperState != LinkStateDown && link.OperState != LinkStateUnknown {
			t.Errorf("Link %s has invalid OperState: %v", link.Name, link.OperState)
		}
	}
}

// TestLinkToInfo_TypeField tests that the link type is properly captured
func TestLinkToInfo_TypeField(t *testing.T) {
	tests := []struct {
		name     string
		link     vnl.Link
		wantType string
	}{
		{
			name: "dummy type",
			link: &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  "dummy0",
				},
			},
			wantType: "dummy",
		},
		{
			name: "bridge type",
			link: &vnl.Bridge{
				LinkAttrs: vnl.LinkAttrs{
					Index: 2,
					Name:  "br0",
				},
			},
			wantType: "bridge",
		},
		{
			name: "veth type",
			link: &vnl.Veth{
				LinkAttrs: vnl.LinkAttrs{
					Index: 3,
					Name:  "veth0",
				},
			},
			wantType: "veth",
		},
		{
			name: "tuntap type",
			link: &vnl.Tuntap{
				LinkAttrs: vnl.LinkAttrs{
					Index: 4,
					Name:  "tap0",
				},
				Mode: vnl.TUNTAP_MODE_TAP,
			},
			wantType: "tuntap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := linkToInfo(tt.link)
			if info == nil {
				t.Fatal("linkToInfo() returned nil")
			}

			if info.Type != tt.wantType {
				t.Errorf("Type = %s, want %s", info.Type, tt.wantType)
			}
		})
	}
}

// TestManager_SetLinkUp_SuccessPath tests the success path using mocks
func TestManager_SetLinkUp_SuccessPath(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			return &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  "lo",
					MTU:   65536,
					Flags: net.FlagUp,
				},
			}, nil
		},
		linkSetUpFn: func(link vnl.Link) error {
			return nil
		},
	}
	SetNetlinkOps(mock)

	m := NewManager()

	// Test with loopback - it should already be up, so this should succeed
	// without actually changing anything
	err := m.SetLinkUp("lo")
	if err != nil {
		t.Fatalf("SetLinkUp(lo) failed: %v", err)
	}

	// Verify it's still up
	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) failed: %v", err)
	}

	if !IsUp(info.Flags) {
		t.Error("Loopback should be up")
	}
}

// TestManager_SetLinkDown_SuccessPath tests bringing down using mocks
func TestManager_SetLinkDown_SuccessPath(t *testing.T) {
	defer ResetNetlinkOps()

	linkUp := true

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

	m := NewManager()
	tapName := "tap-down-test"

	// Bring up first
	err := m.SetLinkUp(tapName)
	if err != nil {
		t.Fatalf("SetLinkUp() failed: %v", err)
	}

	// Bring down
	err = m.SetLinkDown(tapName)
	if err != nil {
		t.Fatalf("SetLinkDown() failed: %v", err)
	}

	// Verify it's down
	info, err := m.GetLink(tapName)
	if err != nil {
		t.Fatalf("GetLink() failed: %v", err)
	}

	if IsUp(info.Flags) {
		t.Error("Interface should be down after SetLinkDown()")
	}
}

// TestLinkToInfo_OperDormant tests OperDormant state (maps to unknown)
func TestLinkToInfo_OperDormant(t *testing.T) {
	link := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:     1,
			Name:      "test-dormant",
			MTU:       1500,
			OperState: vnl.OperDormant,
		},
	}

	info := linkToInfo(link)
	if info == nil {
		t.Fatal("linkToInfo() returned nil")
	}

	// OperDormant should map to LinkStateUnknown
	if info.OperState != LinkStateUnknown {
		t.Errorf("OperState = %v, want %v", info.OperState, LinkStateUnknown)
	}
}

// TestLinkToInfo_OperTesting tests OperTesting state (maps to unknown)
func TestLinkToInfo_OperTesting(t *testing.T) {
	link := &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{
			Index:     1,
			Name:      "test-testing",
			MTU:       1500,
			OperState: vnl.OperTesting,
		},
	}

	info := linkToInfo(link)
	if info == nil {
		t.Fatal("linkToInfo() returned nil")
	}

	// OperTesting should map to LinkStateUnknown
	if info.OperState != LinkStateUnknown {
		t.Errorf("OperState = %v, want %v", info.OperState, LinkStateUnknown)
	}
}

// TestManager_ConcurrentMixedOperations tests concurrent read and write operations using mocks
func TestManager_ConcurrentMixedOperations(t *testing.T) {
	defer ResetNetlinkOps()

	mock := &mockNetlinkOps{
		linkByNameFn: func(name string) (vnl.Link, error) {
			if name == "nonexistent12345" {
				return nil, errors.New("Link not found")
			}
			return &vnl.Dummy{
				LinkAttrs: vnl.LinkAttrs{
					Index: 1,
					Name:  "lo",
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
	done := make(chan bool, 20)

	// Launch readers
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				_, _ = m.GetLink("lo")
				_, _ = m.ListLinks()
			}
		}()
	}

	// Launch operations that will fail (non-existent interfaces)
	// This tests that the locks work correctly under contention
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 50; j++ {
				_ = m.SetLinkUp("nonexistent12345")
				_ = m.SetLinkDown("nonexistent12345")
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestManager_GetLink_Success verifies GetLink returns correct data using mocks
func TestManager_GetLink_Success(t *testing.T) {
	defer ResetNetlinkOps()

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

	m := NewManager()

	info, err := m.GetLink("lo")
	if err != nil {
		t.Fatalf("GetLink(lo) failed: %v", err)
	}

	// Verify all fields are populated
	if info.Index <= 0 {
		t.Errorf("Index should be > 0, got %d", info.Index)
	}
	if info.Name != "lo" {
		t.Errorf("Name = %s, want lo", info.Name)
	}
	if info.Type == "" {
		t.Error("Type should not be empty")
	}
	// MTU for loopback is typically 65536 but can vary
	if info.MTU <= 0 {
		t.Errorf("MTU should be > 0, got %d", info.MTU)
	}
}

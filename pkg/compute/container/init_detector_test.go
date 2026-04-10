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

package container

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestInitSystem_String tests the String method
func TestInitSystem_String(t *testing.T) {
	tests := []struct {
		name     string
		system   InitSystem
		expected string
	}{
		{
			name:     "systemd",
			system:   InitSystemSystemd,
			expected: "systemd",
		},
		{
			name:     "rc",
			system:   InitSystemRC,
			expected: "rc",
		},
		{
			name:     "unknown",
			system:   InitSystemUnknown,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.system.String(); result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestInitSystem_IsValid tests the IsValid method
func TestInitSystem_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		system   InitSystem
		expected bool
	}{
		{
			name:     "systemd is valid",
			system:   InitSystemSystemd,
			expected: true,
		},
		{
			name:     "rc is valid",
			system:   InitSystemRC,
			expected: true,
		},
		{
			name:     "unknown is invalid",
			system:   InitSystemUnknown,
			expected: false,
		},
		{
			name:     "empty is invalid",
			system:   InitSystem(""),
			expected: false,
		},
		{
			name:     "arbitrary is invalid",
			system:   InitSystem("arbitrary"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.system.IsValid(); result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestNewInitSystemDetector tests the constructor
func TestNewInitSystemDetector(t *testing.T) {
	detector := NewInitSystemDetector()

	if detector == nil {
		t.Fatal("NewInitSystemDetector() returned nil")
	}

	if detector.osStatFunc == nil {
		t.Error("osStatFunc should not be nil")
	}
}

// TestNewInitSystemDetectorWithOptions tests the constructor with options
func TestNewInitSystemDetectorWithOptions(t *testing.T) {
	customStatFunc := func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	detector := NewInitSystemDetectorWithOptions(
		WithOSStatFunc(customStatFunc),
	)

	if detector == nil {
		t.Fatal("NewInitSystemDetectorWithOptions() returned nil")
	}
}

// TestInitSystemDetector_Detect tests detection by OS name
func TestInitSystemDetector_Detect(t *testing.T) {
	// Mock stat function that simulates systemd running
	mockSystemdRunning := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}

	detector := NewInitSystemDetectorWithOptions(
		WithOSStatFunc(mockSystemdRunning),
	)

	tests := []struct {
		name     string
		osName   string
		expected InitSystem
	}{
		// Direct matches
		{
			name:     "alpine direct",
			osName:   "alpine",
			expected: InitSystemRC,
		},
		{
			name:     "gentoo direct",
			osName:   "gentoo",
			expected: InitSystemRC,
		},
		{
			name:     "artix direct",
			osName:   "artix",
			expected: InitSystemRC,
		},
		{
			name:     "debian direct",
			osName:   "debian",
			expected: InitSystemSystemd,
		},
		{
			name:     "ubuntu direct",
			osName:   "ubuntu",
			expected: InitSystemSystemd,
		},
		{
			name:     "fedora direct",
			osName:   "fedora",
			expected: InitSystemSystemd,
		},
		{
			name:     "centos direct",
			osName:   "centos",
			expected: InitSystemSystemd,
		},
		{
			name:     "rhel direct",
			osName:   "rhel",
			expected: InitSystemSystemd,
		},
		{
			name:     "rocky direct",
			osName:   "rocky",
			expected: InitSystemSystemd,
		},
		{
			name:     "alma direct",
			osName:   "alma",
			expected: InitSystemSystemd,
		},
		{
			name:     "arch direct",
			osName:   "arch",
			expected: InitSystemSystemd,
		},
		{
			name:     "opensuse direct",
			osName:   "opensuse",
			expected: InitSystemSystemd,
		},
		// Case insensitive
		{
			name:     "Ubuntu uppercase",
			osName:   "Ubuntu",
			expected: InitSystemSystemd,
		},
		{
			name:     "ALPINE uppercase",
			osName:   "ALPINE",
			expected: InitSystemRC,
		},
		// Pattern matches
		{
			name:     "Ubuntu 22.04 pattern",
			osName:   "ubuntu 22.04",
			expected: InitSystemSystemd,
		},
		{
			name:     "Alpine Linux pattern",
			osName:   "Alpine Linux",
			expected: InitSystemRC,
		},
		{
			name:     "Red Hat Enterprise Linux",
			osName:   "Red Hat Enterprise Linux",
			expected: InitSystemSystemd,
		},
		// Empty falls back to runtime detection
		{
			name:     "empty falls back to runtime (systemd)",
			osName:   "",
			expected: InitSystemSystemd, // Mock simulates systemd
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.Detect(tt.osName)
			if result != tt.expected {
				t.Errorf("Detect(%q) = %q, want %q", tt.osName, result, tt.expected)
			}
		})
	}
}

// TestInitSystemDetector_DetectAtRuntime tests runtime detection
func TestInitSystemDetector_DetectAtRuntime(t *testing.T) {
	tests := []struct {
		name     string
		mockStat func(string) (os.FileInfo, error)
		expected InitSystem
	}{
		{
			name: "systemd running",
			mockStat: func(path string) (os.FileInfo, error) {
				if path == "/run/systemd/system" {
					return nil, nil // exists
				}
				return nil, os.ErrNotExist
			},
			expected: InitSystemSystemd,
		},
		{
			name: "openrc with /sbin/openrc",
			mockStat: func(path string) (os.FileInfo, error) {
				if path == "/sbin/openrc" {
					return nil, nil // exists
				}
				return nil, os.ErrNotExist
			},
			expected: InitSystemRC,
		},
		{
			name: "openrc with /sbin/rc-service",
			mockStat: func(path string) (os.FileInfo, error) {
				if path == "/sbin/rc-service" {
					return nil, nil // exists
				}
				return nil, os.ErrNotExist
			},
			expected: InitSystemRC,
		},
		{
			name: "openrc with runlevels",
			mockStat: func(path string) (os.FileInfo, error) {
				if path == "/etc/init.d" || path == "/etc/runlevels" {
					return nil, nil // exists
				}
				return nil, os.ErrNotExist
			},
			expected: InitSystemRC,
		},
		{
			name: "default to systemd when nothing found",
			mockStat: func(path string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
			expected: InitSystemSystemd,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewInitSystemDetectorWithOptions(
				WithOSStatFunc(tt.mockStat),
			)
			result := detector.DetectAtRuntime()
			if result != tt.expected {
				t.Errorf("DetectAtRuntime() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestInitSystemDetector_DetectFromDeviceProfile tests detection from device profile
func TestInitSystemDetector_DetectFromDeviceProfile(t *testing.T) {
	mockSystemdRunning := func(name string) (os.FileInfo, error) {
		if name == "/run/systemd/system" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}

	detector := NewInitSystemDetectorWithOptions(
		WithOSStatFunc(mockSystemdRunning),
	)

	tests := []struct {
		name     string
		profile  *entities.DeviceProfile
		expected InitSystem
	}{
		{
			name:     "nil profile falls back to runtime",
			profile:  nil,
			expected: InitSystemSystemd, // mock simulates systemd
		},
		{
			name: "profile with ubuntu model",
			profile: &entities.DeviceProfile{
				Model: "ubuntu",
			},
			expected: InitSystemSystemd,
		},
		{
			name: "profile with alpine model",
			profile: &entities.DeviceProfile{
				Model: "alpine",
			},
			expected: InitSystemRC,
		},
		{
			name: "profile with empty model",
			profile: &entities.DeviceProfile{
				Model: "",
			},
			expected: InitSystemSystemd, // falls back to runtime
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectFromDeviceProfile(tt.profile)
			if result != tt.expected {
				t.Errorf("DetectFromDeviceProfile() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestInitSystemDetector_GetDefaultForOS tests getting default without runtime fallback
func TestInitSystemDetector_GetDefaultForOS(t *testing.T) {
	detector := NewInitSystemDetector()

	tests := []struct {
		name     string
		osName   string
		expected InitSystem
	}{
		{
			name:     "known systemd OS",
			osName:   "debian",
			expected: InitSystemSystemd,
		},
		{
			name:     "known rc OS",
			osName:   "alpine",
			expected: InitSystemRC,
		},
		{
			name:     "unknown OS returns unknown",
			osName:   "unknownos",
			expected: InitSystemUnknown,
		},
		{
			name:     "empty OS returns unknown",
			osName:   "",
			expected: InitSystemUnknown,
		},
		{
			name:     "pattern match works",
			osName:   "Ubuntu 22.04 LTS",
			expected: InitSystemSystemd,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.GetDefaultForOS(tt.osName)
			if result != tt.expected {
				t.Errorf("GetDefaultForOS(%q) = %q, want %q", tt.osName, result, tt.expected)
			}
		})
	}
}

// TestInitSystemDetector_ListSupportedOS tests listing supported OS names
func TestInitSystemDetector_ListSupportedOS(t *testing.T) {
	detector := NewInitSystemDetector()
	supported := detector.ListSupportedOS()

	if len(supported) == 0 {
		t.Error("ListSupportedOS() returned empty list")
	}

	// Check that expected OS names are present
	expectedOS := []string{"alpine", "gentoo", "artix", "debian", "ubuntu", "fedora", "centos"}
	for _, expected := range expectedOS {
		found := false
		for _, os := range supported {
			if os == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected OS %q not found in supported list", expected)
		}
	}
}

// TestInitSystemDetector_IsSystemdOS tests systemd OS check
func TestInitSystemDetector_IsSystemdOS(t *testing.T) {
	detector := NewInitSystemDetector()

	tests := []struct {
		name     string
		osName   string
		expected bool
	}{
		{"debian is systemd", "debian", true},
		{"ubuntu is systemd", "ubuntu", true},
		{"alpine is not systemd", "alpine", false},
		{"unknown returns false", "unknownos", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.IsSystemdOS(tt.osName)
			if result != tt.expected {
				t.Errorf("IsSystemdOS(%q) = %v, want %v", tt.osName, result, tt.expected)
			}
		})
	}
}

// TestInitSystemDetector_IsRCOS tests rc OS check
func TestInitSystemDetector_IsRCOS(t *testing.T) {
	detector := NewInitSystemDetector()

	tests := []struct {
		name     string
		osName   string
		expected bool
	}{
		{"alpine is rc", "alpine", true},
		{"gentoo is rc", "gentoo", true},
		{"artix is rc", "artix", true},
		{"debian is not rc", "debian", false},
		{"unknown returns false", "unknownos", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.IsRCOS(tt.osName)
			if result != tt.expected {
				t.Errorf("IsRCOS(%q) = %v, want %v", tt.osName, result, tt.expected)
			}
		})
	}
}

// TestOsInitSystemDefaults tests the defaults map directly
func TestOsInitSystemDefaults(t *testing.T) {
	// Verify expected mappings
	rcSystems := []string{"alpine", "gentoo", "artix"}
	for _, os := range rcSystems {
		if osInitSystemDefaults[os] != InitSystemRC {
			t.Errorf("osInitSystemDefaults[%q] = %q, want %q", os, osInitSystemDefaults[os], InitSystemRC)
		}
	}

	systemdSystems := []string{"debian", "ubuntu", "fedora", "centos", "rhel", "rocky", "alma", "arch", "opensuse", "suse"}
	for _, os := range systemdSystems {
		if osInitSystemDefaults[os] != InitSystemSystemd {
			t.Errorf("osInitSystemDefaults[%q] = %q, want %q", os, osInitSystemDefaults[os], InitSystemSystemd)
		}
	}
}

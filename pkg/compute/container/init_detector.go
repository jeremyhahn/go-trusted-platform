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

// Package container provides init system detection and service generation
// for container workloads managed by go-trusted-platform.
package container

import (
	"os"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// InitSystem represents the type of init system
type InitSystem string

const (
	// InitSystemSystemd represents the systemd init system
	InitSystemSystemd InitSystem = "systemd"

	// InitSystemRC represents OpenRC or similar rc-based init systems
	InitSystemRC InitSystem = "rc"

	// InitSystemUnknown represents an unknown init system
	InitSystemUnknown InitSystem = "unknown"
)

// String returns the string representation of InitSystem
func (i InitSystem) String() string {
	return string(i)
}

// IsValid checks if the InitSystem is valid
func (i InitSystem) IsValid() bool {
	switch i {
	case InitSystemSystemd, InitSystemRC:
		return true
	default:
		return false
	}
}

// osInitSystemDefaults maps operating system names to their default init systems.
// This provides sane defaults for common Linux distributions.
var osInitSystemDefaults = map[string]InitSystem{
	// OpenRC-based distributions (rc)
	"alpine": InitSystemRC,
	"gentoo": InitSystemRC,
	"artix":  InitSystemRC,

	// systemd-based distributions
	"debian":   InitSystemSystemd,
	"ubuntu":   InitSystemSystemd,
	"fedora":   InitSystemSystemd,
	"centos":   InitSystemSystemd,
	"rhel":     InitSystemSystemd,
	"rocky":    InitSystemSystemd,
	"alma":     InitSystemSystemd,
	"arch":     InitSystemSystemd,
	"opensuse": InitSystemSystemd,
	"suse":     InitSystemSystemd,
}

// InitSystemDetector provides functionality to detect the init system
// in use on a host operating system. It supports both static detection
// based on OS name and runtime detection by checking for init system markers.
type InitSystemDetector struct {
	// osStatFunc allows overriding os.Stat for testing
	osStatFunc func(name string) (os.FileInfo, error)
}

// NewInitSystemDetector creates a new InitSystemDetector with default settings
func NewInitSystemDetector() *InitSystemDetector {
	return &InitSystemDetector{
		osStatFunc: os.Stat,
	}
}

// InitSystemDetectorOption configures an InitSystemDetector
type InitSystemDetectorOption func(*InitSystemDetector)

// WithOSStatFunc sets a custom os.Stat function for testing
func WithOSStatFunc(fn func(name string) (os.FileInfo, error)) InitSystemDetectorOption {
	return func(d *InitSystemDetector) {
		d.osStatFunc = fn
	}
}

// NewInitSystemDetectorWithOptions creates a new InitSystemDetector with options
func NewInitSystemDetectorWithOptions(opts ...InitSystemDetectorOption) *InitSystemDetector {
	d := NewInitSystemDetector()
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Detect returns the init system based on the provided OS name.
// It looks up the OS name in the osInitSystemDefaults map and returns
// the corresponding init system. If the OS is not found, it falls back
// to pattern matching and ultimately runtime detection.
func (d *InitSystemDetector) Detect(osName string) InitSystem {
	if osName == "" {
		return d.DetectAtRuntime()
	}

	// Normalize the OS name to lowercase for matching
	normalizedOS := strings.ToLower(strings.TrimSpace(osName))

	// Direct lookup in defaults map
	if initSystem, ok := osInitSystemDefaults[normalizedOS]; ok {
		return initSystem
	}

	// Pattern matching for OS families
	initSystem := d.detectByPattern(normalizedOS)
	if initSystem != InitSystemUnknown {
		return initSystem
	}

	// Fall back to runtime detection
	return d.DetectAtRuntime()
}

// detectByPattern attempts to detect the init system by pattern matching
// on the OS name. This handles cases where the OS name contains version
// info or other suffixes.
func (d *InitSystemDetector) detectByPattern(osName string) InitSystem {
	// OpenRC-based patterns
	rcPatterns := []string{"alpine", "gentoo", "artix"}
	for _, pattern := range rcPatterns {
		if strings.Contains(osName, pattern) {
			return InitSystemRC
		}
	}

	// systemd-based patterns
	systemdPatterns := []string{
		"debian", "ubuntu", "fedora", "centos", "rhel",
		"rocky", "alma", "arch", "opensuse", "suse",
		"redhat", "red hat",
	}
	for _, pattern := range systemdPatterns {
		if strings.Contains(osName, pattern) {
			return InitSystemSystemd
		}
	}

	return InitSystemUnknown
}

// DetectAtRuntime performs runtime detection of the init system by
// checking for well-known markers on the filesystem. This is the most
// reliable method when the OS name is unknown or ambiguous.
func (d *InitSystemDetector) DetectAtRuntime() InitSystem {
	// Check for systemd by looking for /run/systemd/system
	// This directory only exists when systemd is running as PID 1
	if _, err := d.osStatFunc("/run/systemd/system"); err == nil {
		return InitSystemSystemd
	}

	// Check for OpenRC by looking for /sbin/openrc or /sbin/rc-service
	if _, err := d.osStatFunc("/sbin/openrc"); err == nil {
		return InitSystemRC
	}
	if _, err := d.osStatFunc("/sbin/rc-service"); err == nil {
		return InitSystemRC
	}

	// Check for OpenRC configuration directory
	if _, err := d.osStatFunc("/etc/init.d"); err == nil {
		// /etc/init.d exists on many systems, but if we got here,
		// it's likely an OpenRC or SysV init system
		if _, err := d.osStatFunc("/etc/runlevels"); err == nil {
			return InitSystemRC
		}
	}

	// Default to systemd as it's the most common
	return InitSystemSystemd
}

// DetectFromDeviceProfile detects the init system from a device profile.
// It checks for an OS name in the profile and uses that for detection.
// If no OS information is available, it falls back to runtime detection.
func (d *InitSystemDetector) DetectFromDeviceProfile(profile *entities.DeviceProfile) InitSystem {
	if profile == nil {
		return d.DetectAtRuntime()
	}

	// Check if the profile has a model field that might contain OS info
	// Note: DeviceProfile currently doesn't have a dedicated OS field,
	// so we check the model as a fallback
	if profile.Model != "" {
		initSystem := d.Detect(profile.Model)
		if initSystem != InitSystemUnknown {
			return initSystem
		}
	}

	// Fall back to runtime detection
	return d.DetectAtRuntime()
}

// GetDefaultForOS returns the default init system for a given OS name
// without falling back to runtime detection. Returns InitSystemUnknown
// if the OS is not in the defaults map.
func (d *InitSystemDetector) GetDefaultForOS(osName string) InitSystem {
	normalizedOS := strings.ToLower(strings.TrimSpace(osName))

	if initSystem, ok := osInitSystemDefaults[normalizedOS]; ok {
		return initSystem
	}

	return d.detectByPattern(normalizedOS)
}

// ListSupportedOS returns a list of all OS names that have explicit
// init system defaults configured.
func (d *InitSystemDetector) ListSupportedOS() []string {
	result := make([]string, 0, len(osInitSystemDefaults))
	for os := range osInitSystemDefaults {
		result = append(result, os)
	}
	return result
}

// IsSystemdOS returns true if the given OS name defaults to systemd
func (d *InitSystemDetector) IsSystemdOS(osName string) bool {
	return d.GetDefaultForOS(osName) == InitSystemSystemd
}

// IsRCOS returns true if the given OS name defaults to OpenRC
func (d *InitSystemDetector) IsRCOS(osName string) bool {
	return d.GetDefaultForOS(osName) == InitSystemRC
}

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

package initrd

import (
	"testing"
)

func TestBootModeString(t *testing.T) {
	tests := []struct {
		mode     BootMode
		expected string
	}{
		{ModeInstall, "install"},
		{ModeBoot, "boot"},
		{ModeRecovery, "recovery"},
		{ModeMaintenance, "maintenance"},
		{BootMode(999), "unknown"},
	}

	for _, tt := range tests {
		result := tt.mode.String()
		if result != tt.expected {
			t.Errorf("BootMode(%d).String() = %s, want %s", tt.mode, result, tt.expected)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				RootDevice:    "/dev/sda2",
				XKMSPath:      "/var/lib/trusted-platform/xkms",
				PCRSelection:  []uint{0, 1, 2, 3, 7},
				UnlockTimeout: 30,
				RetryCount:    3,
			},
			expectErr: false,
		},
		{
			name: "missing root device",
			config: &Config{
				RootDevice:   "",
				XKMSPath:     "/var/lib/trusted-platform/xkms",
				PCRSelection: []uint{0, 1, 2},
			},
			expectErr: true,
		},
		{
			name: "missing xkms path",
			config: &Config{
				RootDevice:   "/dev/sda2",
				XKMSPath:     "",
				PCRSelection: []uint{0, 1, 2},
			},
			expectErr: true,
		},
		{
			name: "missing PCR selection",
			config: &Config{
				RootDevice:   "/dev/sda2",
				XKMSPath:     "/var/lib/trusted-platform/xkms",
				PCRSelection: []uint{},
			},
			expectErr: true,
		},
		{
			name: "nil PCR selection",
			config: &Config{
				RootDevice:   "/dev/sda2",
				XKMSPath:     "/var/lib/trusted-platform/xkms",
				PCRSelection: nil,
			},
			expectErr: true,
		},
		{
			name: "zero unlock timeout - should default",
			config: &Config{
				RootDevice:    "/dev/sda2",
				XKMSPath:      "/var/lib/trusted-platform/xkms",
				PCRSelection:  []uint{0, 1, 2},
				UnlockTimeout: 0,
			},
			expectErr: false,
		},
		{
			name: "zero retry count - should default",
			config: &Config{
				RootDevice:   "/dev/sda2",
				XKMSPath:     "/var/lib/trusted-platform/xkms",
				PCRSelection: []uint{0, 1, 2},
				RetryCount:   0,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}

			// Check default values are set
			if !tt.expectErr {
				if tt.config.UnlockTimeout == 0 {
					t.Error("UnlockTimeout should be defaulted to 30")
				}
				if tt.config.RetryCount == 0 {
					t.Error("RetryCount should be defaulted to 3")
				}
			}
		})
	}
}

func TestConfigValidateDefaults(t *testing.T) {
	config := &Config{
		RootDevice:   "/dev/sda2",
		XKMSPath:     "/var/lib/trusted-platform/xkms",
		PCRSelection: []uint{0, 1, 2},
		// UnlockTimeout and RetryCount not set
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if config.UnlockTimeout != 30 {
		t.Errorf("expected default UnlockTimeout 30, got %d", config.UnlockTimeout)
	}

	if config.RetryCount != 3 {
		t.Errorf("expected default RetryCount 3, got %d", config.RetryCount)
	}
}

func TestConfigValidateNegativeTimeout(t *testing.T) {
	config := &Config{
		RootDevice:    "/dev/sda2",
		XKMSPath:      "/var/lib/trusted-platform/xkms",
		PCRSelection:  []uint{0, 1, 2},
		UnlockTimeout: -5,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Negative timeout should be reset to default
	if config.UnlockTimeout != 30 {
		t.Errorf("expected default UnlockTimeout 30, got %d", config.UnlockTimeout)
	}
}

func TestConfigValidateNegativeRetryCount(t *testing.T) {
	config := &Config{
		RootDevice:   "/dev/sda2",
		XKMSPath:     "/var/lib/trusted-platform/xkms",
		PCRSelection: []uint{0, 1, 2},
		RetryCount:   -2,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Negative retry count should be reset to default
	if config.RetryCount != 3 {
		t.Errorf("expected default RetryCount 3, got %d", config.RetryCount)
	}
}

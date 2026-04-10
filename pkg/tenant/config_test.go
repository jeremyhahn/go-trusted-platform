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

package tenant

import (
	"errors"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Verify VLAN defaults
	if cfg.DefaultVLANRangeStart != 100 {
		t.Errorf("DefaultVLANRangeStart = %d, want 100", cfg.DefaultVLANRangeStart)
	}
	if cfg.DefaultVLANRangeSize != 100 {
		t.Errorf("DefaultVLANRangeSize = %d, want 100", cfg.DefaultVLANRangeSize)
	}
	if cfg.MaxVLANRangeSize != 1000 {
		t.Errorf("MaxVLANRangeSize = %d, want 1000", cfg.MaxVLANRangeSize)
	}

	// Verify bridge prefix
	if cfg.BridgePrefix != "br-tenant-" {
		t.Errorf("BridgePrefix = %q, want %q", cfg.BridgePrefix, "br-tenant-")
	}

	// Verify compute quota defaults
	if cfg.DefaultComputeQuota.MaxVMs != 10 {
		t.Errorf("DefaultComputeQuota.MaxVMs = %d, want 10", cfg.DefaultComputeQuota.MaxVMs)
	}
	if cfg.DefaultComputeQuota.MaxContainers != 50 {
		t.Errorf("DefaultComputeQuota.MaxContainers = %d, want 50", cfg.DefaultComputeQuota.MaxContainers)
	}
	if cfg.DefaultComputeQuota.MaxVCPUs != 32 {
		t.Errorf("DefaultComputeQuota.MaxVCPUs = %d, want 32", cfg.DefaultComputeQuota.MaxVCPUs)
	}
	if cfg.DefaultComputeQuota.MaxMemoryMB != 65536 {
		t.Errorf("DefaultComputeQuota.MaxMemoryMB = %d, want 65536", cfg.DefaultComputeQuota.MaxMemoryMB)
	}
	if cfg.DefaultComputeQuota.MaxDiskGB != 1024 {
		t.Errorf("DefaultComputeQuota.MaxDiskGB = %d, want 1024", cfg.DefaultComputeQuota.MaxDiskGB)
	}

	// Verify network quota defaults
	if cfg.DefaultNetworkQuota.MaxBridges != 5 {
		t.Errorf("DefaultNetworkQuota.MaxBridges = %d, want 5", cfg.DefaultNetworkQuota.MaxBridges)
	}
	if cfg.DefaultNetworkQuota.MaxPorts != 100 {
		t.Errorf("DefaultNetworkQuota.MaxPorts = %d, want 100", cfg.DefaultNetworkQuota.MaxPorts)
	}
	if cfg.DefaultNetworkQuota.MaxBandwidthMbps != 10000 {
		t.Errorf("DefaultNetworkQuota.MaxBandwidthMbps = %d, want 10000", cfg.DefaultNetworkQuota.MaxBandwidthMbps)
	}

	// Verify storage quota defaults
	if cfg.DefaultStorageQuota.MaxVolumesGB != 2048 {
		t.Errorf("DefaultStorageQuota.MaxVolumesGB = %d, want 2048", cfg.DefaultStorageQuota.MaxVolumesGB)
	}
	if cfg.DefaultStorageQuota.MaxSnapshots != 100 {
		t.Errorf("DefaultStorageQuota.MaxSnapshots = %d, want 100", cfg.DefaultStorageQuota.MaxSnapshots)
	}

	// Verify DEK isolation
	if !cfg.EnableDEKIsolation {
		t.Error("EnableDEKIsolation should be true by default")
	}
}

func TestDefaultConfig_Validate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultConfig().Validate() unexpected error: %v", err)
	}
}

func TestConfig_Validate_VLANRangeStart(t *testing.T) {
	tests := []struct {
		name      string
		start     uint16
		expectErr bool
	}{
		{"valid minimum", 1, false},
		{"valid middle", 2000, false},
		{"valid maximum", 4094, false},
		{"invalid zero", 0, true},
		{"invalid too high", 4095, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DefaultVLANRangeStart = tt.start
			// Adjust range size to avoid exceeding max VLAN
			if tt.start > 3994 {
				cfg.DefaultVLANRangeSize = 1
			}

			err := cfg.Validate()

			if tt.expectErr {
				if err == nil {
					t.Error("Validate() expected error")
					return
				}
				var configErr ErrConfigValidation
				if !errors.As(err, &configErr) {
					t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
				}
				if configErr.Field != "DefaultVLANRangeStart" {
					t.Errorf("ErrConfigValidation.Field = %q, want %q", configErr.Field, "DefaultVLANRangeStart")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfig_Validate_VLANRangeSize(t *testing.T) {
	tests := []struct {
		name      string
		size      uint16
		expectErr bool
	}{
		{"valid minimum", 1, false},
		{"valid middle", 500, false},
		{"invalid zero", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DefaultVLANRangeSize = tt.size

			err := cfg.Validate()

			if tt.expectErr {
				if err == nil {
					t.Error("Validate() expected error")
					return
				}
				var configErr ErrConfigValidation
				if !errors.As(err, &configErr) {
					t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfig_Validate_MaxVLANRangeSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxVLANRangeSize = 50 // Less than DefaultVLANRangeSize (100)

	err := cfg.Validate()

	if err == nil {
		t.Error("Validate() expected error for MaxVLANRangeSize < DefaultVLANRangeSize")
		return
	}

	var configErr ErrConfigValidation
	if !errors.As(err, &configErr) {
		t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
	}
	if configErr.Field != "MaxVLANRangeSize" {
		t.Errorf("ErrConfigValidation.Field = %q, want %q", configErr.Field, "MaxVLANRangeSize")
	}
}

func TestConfig_Validate_VLANRangeExceedsMax(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DefaultVLANRangeStart = 4000
	cfg.DefaultVLANRangeSize = 100 // Would exceed 4094

	err := cfg.Validate()

	if err == nil {
		t.Error("Validate() expected error for VLAN range exceeding 4094")
		return
	}

	var configErr ErrConfigValidation
	if !errors.As(err, &configErr) {
		t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
	}
}

func TestConfig_Validate_BridgePrefix(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BridgePrefix = ""

	err := cfg.Validate()

	if err == nil {
		t.Error("Validate() expected error for empty BridgePrefix")
		return
	}

	var configErr ErrConfigValidation
	if !errors.As(err, &configErr) {
		t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
	}
	if configErr.Field != "BridgePrefix" {
		t.Errorf("ErrConfigValidation.Field = %q, want %q", configErr.Field, "BridgePrefix")
	}
}

func TestConfig_Validate_ComputeQuota(t *testing.T) {
	tests := []struct {
		name       string
		modifyFunc func(*Config)
		field      string
	}{
		{
			name:       "negative MaxVMs",
			modifyFunc: func(c *Config) { c.DefaultComputeQuota.MaxVMs = -1 },
			field:      "DefaultComputeQuota.MaxVMs",
		},
		{
			name:       "negative MaxContainers",
			modifyFunc: func(c *Config) { c.DefaultComputeQuota.MaxContainers = -1 },
			field:      "DefaultComputeQuota.MaxContainers",
		},
		{
			name:       "negative MaxVCPUs",
			modifyFunc: func(c *Config) { c.DefaultComputeQuota.MaxVCPUs = -1 },
			field:      "DefaultComputeQuota.MaxVCPUs",
		},
		{
			name:       "negative MaxMemoryMB",
			modifyFunc: func(c *Config) { c.DefaultComputeQuota.MaxMemoryMB = -1 },
			field:      "DefaultComputeQuota.MaxMemoryMB",
		},
		{
			name:       "negative MaxDiskGB",
			modifyFunc: func(c *Config) { c.DefaultComputeQuota.MaxDiskGB = -1 },
			field:      "DefaultComputeQuota.MaxDiskGB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modifyFunc(cfg)

			err := cfg.Validate()

			if err == nil {
				t.Error("Validate() expected error")
				return
			}

			var configErr ErrConfigValidation
			if !errors.As(err, &configErr) {
				t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
			}
			if configErr.Field != tt.field {
				t.Errorf("ErrConfigValidation.Field = %q, want %q", configErr.Field, tt.field)
			}
		})
	}
}

func TestConfig_Validate_NetworkQuota(t *testing.T) {
	tests := []struct {
		name       string
		modifyFunc func(*Config)
		field      string
	}{
		{
			name:       "negative MaxBridges",
			modifyFunc: func(c *Config) { c.DefaultNetworkQuota.MaxBridges = -1 },
			field:      "DefaultNetworkQuota.MaxBridges",
		},
		{
			name:       "negative MaxPorts",
			modifyFunc: func(c *Config) { c.DefaultNetworkQuota.MaxPorts = -1 },
			field:      "DefaultNetworkQuota.MaxPorts",
		},
		{
			name:       "negative MaxBandwidthMbps",
			modifyFunc: func(c *Config) { c.DefaultNetworkQuota.MaxBandwidthMbps = -1 },
			field:      "DefaultNetworkQuota.MaxBandwidthMbps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modifyFunc(cfg)

			err := cfg.Validate()

			if err == nil {
				t.Error("Validate() expected error")
				return
			}

			var configErr ErrConfigValidation
			if !errors.As(err, &configErr) {
				t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
			}
			if configErr.Field != tt.field {
				t.Errorf("ErrConfigValidation.Field = %q, want %q", configErr.Field, tt.field)
			}
		})
	}
}

func TestConfig_Validate_StorageQuota(t *testing.T) {
	tests := []struct {
		name       string
		modifyFunc func(*Config)
		field      string
	}{
		{
			name:       "negative MaxVolumesGB",
			modifyFunc: func(c *Config) { c.DefaultStorageQuota.MaxVolumesGB = -1 },
			field:      "DefaultStorageQuota.MaxVolumesGB",
		},
		{
			name:       "negative MaxSnapshots",
			modifyFunc: func(c *Config) { c.DefaultStorageQuota.MaxSnapshots = -1 },
			field:      "DefaultStorageQuota.MaxSnapshots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modifyFunc(cfg)

			err := cfg.Validate()

			if err == nil {
				t.Error("Validate() expected error")
				return
			}

			var configErr ErrConfigValidation
			if !errors.As(err, &configErr) {
				t.Errorf("Validate() error type = %T, want ErrConfigValidation", err)
			}
			if configErr.Field != tt.field {
				t.Errorf("ErrConfigValidation.Field = %q, want %q", configErr.Field, tt.field)
			}
		})
	}
}

func TestConfig_Clone_NilReceiver(t *testing.T) {
	var cfg *Config
	result := cfg.Clone()
	if result != nil {
		t.Errorf("Clone() on nil receiver = %v, want nil", result)
	}
}

func TestConfig_Clone_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	clone := cfg.Clone()

	if clone == nil {
		t.Fatal("Clone() returned nil")
	}
	if clone == cfg {
		t.Error("Clone() should return a different pointer")
	}

	// Verify values are copied
	if clone.DefaultVLANRangeStart != cfg.DefaultVLANRangeStart {
		t.Error("Clone() should copy DefaultVLANRangeStart")
	}
	if clone.BridgePrefix != cfg.BridgePrefix {
		t.Error("Clone() should copy BridgePrefix")
	}
	if clone.EnableDEKIsolation != cfg.EnableDEKIsolation {
		t.Error("Clone() should copy EnableDEKIsolation")
	}
}

func TestConfig_Clone_Independence(t *testing.T) {
	cfg := DefaultConfig()
	clone := cfg.Clone()

	// Modify original
	cfg.DefaultVLANRangeStart = 500
	cfg.BridgePrefix = "modified-"

	// Clone should not be affected
	if clone.DefaultVLANRangeStart == 500 {
		t.Error("Clone should be independent from original")
	}
	if clone.BridgePrefix == "modified-" {
		t.Error("Clone should be independent from original")
	}
}

func TestConfig_WithVLANRange(t *testing.T) {
	cfg := DefaultConfig()
	result := cfg.WithVLANRange(200, 50, 500)

	if result == nil {
		t.Fatal("WithVLANRange() returned nil")
	}
	if result == cfg {
		t.Error("WithVLANRange() should return a new config")
	}
	if result.DefaultVLANRangeStart != 200 {
		t.Errorf("WithVLANRange().DefaultVLANRangeStart = %d, want 200", result.DefaultVLANRangeStart)
	}
	if result.DefaultVLANRangeSize != 50 {
		t.Errorf("WithVLANRange().DefaultVLANRangeSize = %d, want 50", result.DefaultVLANRangeSize)
	}
	if result.MaxVLANRangeSize != 500 {
		t.Errorf("WithVLANRange().MaxVLANRangeSize = %d, want 500", result.MaxVLANRangeSize)
	}

	// Original should not be modified
	if cfg.DefaultVLANRangeStart == 200 {
		t.Error("WithVLANRange() should not modify original")
	}
}

func TestConfig_WithBridgePrefix(t *testing.T) {
	cfg := DefaultConfig()
	result := cfg.WithBridgePrefix("custom-br-")

	if result == nil {
		t.Fatal("WithBridgePrefix() returned nil")
	}
	if result == cfg {
		t.Error("WithBridgePrefix() should return a new config")
	}
	if result.BridgePrefix != "custom-br-" {
		t.Errorf("WithBridgePrefix().BridgePrefix = %q, want %q", result.BridgePrefix, "custom-br-")
	}

	// Original should not be modified
	if cfg.BridgePrefix == "custom-br-" {
		t.Error("WithBridgePrefix() should not modify original")
	}
}

func TestConfig_WithComputeQuota(t *testing.T) {
	cfg := DefaultConfig()
	quota := ComputeQuota{
		MaxVMs:        20,
		MaxContainers: 100,
		MaxVCPUs:      64,
		MaxMemoryMB:   131072,
		MaxDiskGB:     2048,
	}

	result := cfg.WithComputeQuota(quota)

	if result == nil {
		t.Fatal("WithComputeQuota() returned nil")
	}
	if result == cfg {
		t.Error("WithComputeQuota() should return a new config")
	}
	if result.DefaultComputeQuota.MaxVMs != 20 {
		t.Errorf("WithComputeQuota().DefaultComputeQuota.MaxVMs = %d, want 20", result.DefaultComputeQuota.MaxVMs)
	}

	// Original should not be modified
	if cfg.DefaultComputeQuota.MaxVMs == 20 {
		t.Error("WithComputeQuota() should not modify original")
	}
}

func TestConfig_WithNetworkQuota(t *testing.T) {
	cfg := DefaultConfig()
	quota := NetworkQuota{
		MaxBridges:       10,
		MaxPorts:         200,
		MaxBandwidthMbps: 25000,
	}

	result := cfg.WithNetworkQuota(quota)

	if result == nil {
		t.Fatal("WithNetworkQuota() returned nil")
	}
	if result == cfg {
		t.Error("WithNetworkQuota() should return a new config")
	}
	if result.DefaultNetworkQuota.MaxBridges != 10 {
		t.Errorf("WithNetworkQuota().DefaultNetworkQuota.MaxBridges = %d, want 10", result.DefaultNetworkQuota.MaxBridges)
	}

	// Original should not be modified
	if cfg.DefaultNetworkQuota.MaxBridges == 10 {
		t.Error("WithNetworkQuota() should not modify original")
	}
}

func TestConfig_WithStorageQuota(t *testing.T) {
	cfg := DefaultConfig()
	quota := StorageQuota{
		MaxVolumesGB: 4096,
		MaxSnapshots: 200,
	}

	result := cfg.WithStorageQuota(quota)

	if result == nil {
		t.Fatal("WithStorageQuota() returned nil")
	}
	if result == cfg {
		t.Error("WithStorageQuota() should return a new config")
	}
	if result.DefaultStorageQuota.MaxVolumesGB != 4096 {
		t.Errorf("WithStorageQuota().DefaultStorageQuota.MaxVolumesGB = %d, want 4096", result.DefaultStorageQuota.MaxVolumesGB)
	}

	// Original should not be modified
	if cfg.DefaultStorageQuota.MaxVolumesGB == 4096 {
		t.Error("WithStorageQuota() should not modify original")
	}
}

func TestConfig_WithDEKIsolation(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{"enable DEK isolation", true},
		{"disable DEK isolation", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.EnableDEKIsolation = !tt.enabled // Start with opposite value

			result := cfg.WithDEKIsolation(tt.enabled)

			if result == nil {
				t.Fatal("WithDEKIsolation() returned nil")
			}
			if result == cfg {
				t.Error("WithDEKIsolation() should return a new config")
			}
			if result.EnableDEKIsolation != tt.enabled {
				t.Errorf("WithDEKIsolation().EnableDEKIsolation = %v, want %v", result.EnableDEKIsolation, tt.enabled)
			}

			// Original should not be modified
			if cfg.EnableDEKIsolation == tt.enabled {
				t.Error("WithDEKIsolation() should not modify original")
			}
		})
	}
}

func TestConfig_BuilderChaining(t *testing.T) {
	cfg := DefaultConfig().
		WithVLANRange(200, 50, 500).
		WithBridgePrefix("test-br-").
		WithDEKIsolation(false)

	if cfg.DefaultVLANRangeStart != 200 {
		t.Errorf("Builder chain DefaultVLANRangeStart = %d, want 200", cfg.DefaultVLANRangeStart)
	}
	if cfg.BridgePrefix != "test-br-" {
		t.Errorf("Builder chain BridgePrefix = %q, want %q", cfg.BridgePrefix, "test-br-")
	}
	if cfg.EnableDEKIsolation != false {
		t.Errorf("Builder chain EnableDEKIsolation = %v, want false", cfg.EnableDEKIsolation)
	}
}

func TestConfig_ZeroValues(t *testing.T) {
	cfg := &Config{
		DefaultVLANRangeStart: 100,
		DefaultVLANRangeSize:  100,
		MaxVLANRangeSize:      100,
		BridgePrefix:          "br-",
		// All quota fields are zero
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Config with zero quota values should be valid: %v", err)
	}
}

// Tests for DEK configuration

func TestConfig_ValidateDEKConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantError bool
	}{
		{
			name: "valid DEK config with aes-256-gcm",
			config: &Config{
				DefaultVLANRangeStart: 100,
				DefaultVLANRangeSize:  100,
				MaxVLANRangeSize:      1000,
				BridgePrefix:          "br-tenant-",
				EnableDEKIsolation:    true,
				DEKAlgorithm:          DEKAlgorithmAES256GCM,
				DEKWarningPercent:     80,
			},
			wantError: false,
		},
		{
			name: "valid DEK config with chacha20-poly1305",
			config: &Config{
				DefaultVLANRangeStart: 100,
				DefaultVLANRangeSize:  100,
				MaxVLANRangeSize:      1000,
				BridgePrefix:          "br-tenant-",
				EnableDEKIsolation:    true,
				DEKAlgorithm:          DEKAlgorithmChaCha20Poly1305,
				DEKWarningPercent:     50,
			},
			wantError: false,
		},
		{
			name: "invalid DEK algorithm",
			config: &Config{
				DefaultVLANRangeStart: 100,
				DefaultVLANRangeSize:  100,
				MaxVLANRangeSize:      1000,
				BridgePrefix:          "br-tenant-",
				EnableDEKIsolation:    true,
				DEKAlgorithm:          "invalid-algorithm",
				DEKWarningPercent:     80,
			},
			wantError: true,
		},
		{
			name: "invalid warning percent too high",
			config: &Config{
				DefaultVLANRangeStart: 100,
				DefaultVLANRangeSize:  100,
				MaxVLANRangeSize:      1000,
				BridgePrefix:          "br-tenant-",
				EnableDEKIsolation:    true,
				DEKAlgorithm:          DEKAlgorithmAES256GCM,
				DEKWarningPercent:     101,
			},
			wantError: true,
		},
		{
			name: "invalid warning percent negative",
			config: &Config{
				DefaultVLANRangeStart: 100,
				DefaultVLANRangeSize:  100,
				MaxVLANRangeSize:      1000,
				BridgePrefix:          "br-tenant-",
				EnableDEKIsolation:    true,
				DEKAlgorithm:          DEKAlgorithmAES256GCM,
				DEKWarningPercent:     -1,
			},
			wantError: true,
		},
		{
			name: "DEK validation skipped when disabled",
			config: &Config{
				DefaultVLANRangeStart: 100,
				DefaultVLANRangeSize:  100,
				MaxVLANRangeSize:      1000,
				BridgePrefix:          "br-tenant-",
				EnableDEKIsolation:    false,
				DEKAlgorithm:          "invalid-algorithm", // Should be ignored
				DEKWarningPercent:     -1,                  // Should be ignored
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Config.Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestDefaultConfig_DEKSettings(t *testing.T) {
	config := DefaultConfig()

	if !config.EnableDEKIsolation {
		t.Error("expected EnableDEKIsolation to be true by default")
	}

	if config.DEKAlgorithm != DEKAlgorithmAES256GCM {
		t.Errorf("DEKAlgorithm = %q, want %q", config.DEKAlgorithm, DEKAlgorithmAES256GCM)
	}

	if config.DEKMaxOperations != 0 {
		t.Errorf("DEKMaxOperations = %d, want 0", config.DEKMaxOperations)
	}

	if config.DEKMaxBytes != 0 {
		t.Errorf("DEKMaxBytes = %d, want 0", config.DEKMaxBytes)
	}

	if config.DEKWarningPercent != 80 {
		t.Errorf("DEKWarningPercent = %d, want 80", config.DEKWarningPercent)
	}
}

func TestConfig_Clone_DEKSettings(t *testing.T) {
	config := &Config{
		DefaultVLANRangeStart: 100,
		DefaultVLANRangeSize:  100,
		MaxVLANRangeSize:      1000,
		BridgePrefix:          "br-tenant-",
		EnableDEKIsolation:    true,
		DEKAlgorithm:          DEKAlgorithmChaCha20Poly1305,
		DEKMaxOperations:      1000000,
		DEKMaxBytes:           1024 * 1024 * 1024,
		DEKWarningPercent:     75,
	}

	clone := config.Clone()

	if clone.EnableDEKIsolation != config.EnableDEKIsolation {
		t.Error("Clone().EnableDEKIsolation mismatch")
	}
	if clone.DEKAlgorithm != config.DEKAlgorithm {
		t.Error("Clone().DEKAlgorithm mismatch")
	}
	if clone.DEKMaxOperations != config.DEKMaxOperations {
		t.Error("Clone().DEKMaxOperations mismatch")
	}
	if clone.DEKMaxBytes != config.DEKMaxBytes {
		t.Error("Clone().DEKMaxBytes mismatch")
	}
	if clone.DEKWarningPercent != config.DEKWarningPercent {
		t.Error("Clone().DEKWarningPercent mismatch")
	}
}

func TestConfig_WithDEKConfig(t *testing.T) {
	config := DefaultConfig()

	newConfig := config.WithDEKConfig(
		DEKAlgorithmChaCha20Poly1305,
		500000,
		1024*1024*512,
		90,
	)

	if newConfig.DEKAlgorithm != DEKAlgorithmChaCha20Poly1305 {
		t.Errorf("DEKAlgorithm = %q, want %q", newConfig.DEKAlgorithm, DEKAlgorithmChaCha20Poly1305)
	}
	if newConfig.DEKMaxOperations != 500000 {
		t.Errorf("DEKMaxOperations = %d, want 500000", newConfig.DEKMaxOperations)
	}
	if newConfig.DEKMaxBytes != 1024*1024*512 {
		t.Errorf("DEKMaxBytes = %d, want %d", newConfig.DEKMaxBytes, 1024*1024*512)
	}
	if newConfig.DEKWarningPercent != 90 {
		t.Errorf("DEKWarningPercent = %d, want 90", newConfig.DEKWarningPercent)
	}

	// Original should be unchanged
	if config.DEKAlgorithm != DEKAlgorithmAES256GCM {
		t.Error("original config should not be modified")
	}
}

func TestDEKAlgorithmConstants(t *testing.T) {
	algorithms := []string{
		DEKAlgorithmAES128GCM,
		DEKAlgorithmAES192GCM,
		DEKAlgorithmAES256GCM,
		DEKAlgorithmChaCha20Poly1305,
		DEKAlgorithmXChaCha20Poly1305,
	}

	for _, alg := range algorithms {
		config := &Config{
			DefaultVLANRangeStart: 100,
			DefaultVLANRangeSize:  100,
			MaxVLANRangeSize:      1000,
			BridgePrefix:          "br-tenant-",
			EnableDEKIsolation:    true,
			DEKAlgorithm:          alg,
			DEKWarningPercent:     80,
		}

		if err := config.Validate(); err != nil {
			t.Errorf("algorithm %q should be valid, got error: %v", alg, err)
		}
	}
}

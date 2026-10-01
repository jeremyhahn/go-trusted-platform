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

// Config holds configuration for tenant management.
type Config struct {
	// Quota defaults
	DefaultComputeQuota ComputeQuota
	DefaultNetworkQuota NetworkQuota
	DefaultStorageQuota StorageQuota

	// Key isolation
	EnableDEKIsolation bool   // Enable KMS-based Data Encryption Key isolation per tenant
	DEKAlgorithm       string // DEK algorithm (default: "aes-256-gcm")
	DEKMaxOperations   uint64 // Maximum operations before rotation (0 = unlimited)
	DEKMaxBytes        uint64 // Maximum bytes encrypted before rotation (0 = unlimited)
	DEKWarningPercent  int32  // Warning threshold percentage (default: 80)
}

// Supported DEK algorithms
const (
	DEKAlgorithmAES128GCM         = "aes-128-gcm"
	DEKAlgorithmAES192GCM         = "aes-192-gcm"
	DEKAlgorithmAES256GCM         = "aes-256-gcm"
	DEKAlgorithmChaCha20Poly1305  = "chacha20-poly1305"
	DEKAlgorithmXChaCha20Poly1305 = "xchacha20-poly1305"
)

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		// Default compute quota
		DefaultComputeQuota: ComputeQuota{
			MaxVMs:        10,
			MaxContainers: 50,
			MaxVCPUs:      32,
			MaxMemoryMB:   65536, // 64 GB
			MaxDiskGB:     1024,  // 1 TB
		},

		// Default network quota
		DefaultNetworkQuota: NetworkQuota{
			MaxBridges:       5,
			MaxPorts:         100,
			MaxBandwidthMbps: 10000, // 10 Gbps
		},

		// Default storage quota
		DefaultStorageQuota: StorageQuota{
			MaxVolumesGB: 2048, // 2 TB
			MaxSnapshots: 100,
		},

		// Key isolation defaults
		EnableDEKIsolation: true,
		DEKAlgorithm:       DEKAlgorithmAES256GCM,
		DEKMaxOperations:   0,  // unlimited by default
		DEKMaxBytes:        0,  // unlimited by default
		DEKWarningPercent:  80, // warn at 80% usage
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate quota defaults
	if err := c.validateComputeQuota(); err != nil {
		return err
	}

	if err := c.validateNetworkQuota(); err != nil {
		return err
	}

	if err := c.validateStorageQuota(); err != nil {
		return err
	}

	// Validate DEK configuration when enabled
	if c.EnableDEKIsolation {
		if err := c.validateDEKConfig(); err != nil {
			return err
		}
	}

	return nil
}

// validateComputeQuota validates the default compute quota configuration.
func (c *Config) validateComputeQuota() error {
	if c.DefaultComputeQuota.MaxVMs < 0 {
		return ErrConfigValidation{
			Field:  "DefaultComputeQuota.MaxVMs",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultComputeQuota.MaxContainers < 0 {
		return ErrConfigValidation{
			Field:  "DefaultComputeQuota.MaxContainers",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultComputeQuota.MaxVCPUs < 0 {
		return ErrConfigValidation{
			Field:  "DefaultComputeQuota.MaxVCPUs",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultComputeQuota.MaxMemoryMB < 0 {
		return ErrConfigValidation{
			Field:  "DefaultComputeQuota.MaxMemoryMB",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultComputeQuota.MaxDiskGB < 0 {
		return ErrConfigValidation{
			Field:  "DefaultComputeQuota.MaxDiskGB",
			Reason: "must be non-negative",
		}
	}

	return nil
}

// validateNetworkQuota validates the default network quota configuration.
func (c *Config) validateNetworkQuota() error {
	if c.DefaultNetworkQuota.MaxBridges < 0 {
		return ErrConfigValidation{
			Field:  "DefaultNetworkQuota.MaxBridges",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultNetworkQuota.MaxPorts < 0 {
		return ErrConfigValidation{
			Field:  "DefaultNetworkQuota.MaxPorts",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultNetworkQuota.MaxBandwidthMbps < 0 {
		return ErrConfigValidation{
			Field:  "DefaultNetworkQuota.MaxBandwidthMbps",
			Reason: "must be non-negative",
		}
	}

	return nil
}

// validateStorageQuota validates the default storage quota configuration.
func (c *Config) validateStorageQuota() error {
	if c.DefaultStorageQuota.MaxVolumesGB < 0 {
		return ErrConfigValidation{
			Field:  "DefaultStorageQuota.MaxVolumesGB",
			Reason: "must be non-negative",
		}
	}

	if c.DefaultStorageQuota.MaxSnapshots < 0 {
		return ErrConfigValidation{
			Field:  "DefaultStorageQuota.MaxSnapshots",
			Reason: "must be non-negative",
		}
	}

	return nil
}

// validateDEKConfig validates the DEK isolation configuration.
func (c *Config) validateDEKConfig() error {
	// Validate algorithm
	validAlgorithms := map[string]bool{
		DEKAlgorithmAES128GCM:         true,
		DEKAlgorithmAES192GCM:         true,
		DEKAlgorithmAES256GCM:         true,
		DEKAlgorithmChaCha20Poly1305:  true,
		DEKAlgorithmXChaCha20Poly1305: true,
	}

	if c.DEKAlgorithm != "" && !validAlgorithms[c.DEKAlgorithm] {
		return ErrConfigValidation{
			Field:  "DEKAlgorithm",
			Reason: "must be one of: aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-poly1305, xchacha20-poly1305",
		}
	}

	// Validate warning percent
	if c.DEKWarningPercent < 0 || c.DEKWarningPercent > 100 {
		return ErrConfigValidation{
			Field:  "DEKWarningPercent",
			Reason: "must be between 0 and 100",
		}
	}

	return nil
}

// Clone creates a deep copy of the configuration.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	return &Config{
		DefaultComputeQuota: c.DefaultComputeQuota,
		DefaultNetworkQuota: c.DefaultNetworkQuota,
		DefaultStorageQuota: c.DefaultStorageQuota,
		EnableDEKIsolation:  c.EnableDEKIsolation,
		DEKAlgorithm:        c.DEKAlgorithm,
		DEKMaxOperations:    c.DEKMaxOperations,
		DEKMaxBytes:         c.DEKMaxBytes,
		DEKWarningPercent:   c.DEKWarningPercent,
	}
}

// WithComputeQuota returns a copy of the config with updated compute quota.
func (c *Config) WithComputeQuota(quota ComputeQuota) *Config {
	clone := c.Clone()
	clone.DefaultComputeQuota = quota
	return clone
}

// WithNetworkQuota returns a copy of the config with updated network quota.
func (c *Config) WithNetworkQuota(quota NetworkQuota) *Config {
	clone := c.Clone()
	clone.DefaultNetworkQuota = quota
	return clone
}

// WithStorageQuota returns a copy of the config with updated storage quota.
func (c *Config) WithStorageQuota(quota StorageQuota) *Config {
	clone := c.Clone()
	clone.DefaultStorageQuota = quota
	return clone
}

// WithDEKIsolation returns a copy of the config with updated DEK isolation setting.
func (c *Config) WithDEKIsolation(enabled bool) *Config {
	clone := c.Clone()
	clone.EnableDEKIsolation = enabled
	return clone
}

// WithDEKConfig returns a copy of the config with updated DEK configuration.
func (c *Config) WithDEKConfig(algorithm string, maxOps, maxBytes uint64, warningPercent int32) *Config {
	clone := c.Clone()
	clone.DEKAlgorithm = algorithm
	clone.DEKMaxOperations = maxOps
	clone.DEKMaxBytes = maxBytes
	clone.DEKWarningPercent = warningPercent
	return clone
}

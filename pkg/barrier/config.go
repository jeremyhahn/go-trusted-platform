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

package barrier

const (
	// SealStrategySoftware uses a software-based encryption key.
	SealStrategySoftware = "software"

	// SealStrategyTPM2 uses a TPM 2.0 to seal and unseal the barrier key.
	SealStrategyTPM2 = "tpm2"

	// SealStrategyPKCS11 uses a PKCS#11 hardware token to protect the barrier key.
	SealStrategyPKCS11 = "pkcs11"

	// DefaultSealStrategy is the default seal strategy when none is specified.
	DefaultSealStrategy = SealStrategySoftware
)

// Config holds barrier manager configuration.
type Config struct {
	// AutoUnseal enables automatic unsealing via TPM at startup.
	AutoUnseal bool `yaml:"auto_unseal" json:"auto_unseal" mapstructure:"auto_unseal"`

	// SealStrategy is the preferred sealing strategy (software, tpm2, pkcs11).
	SealStrategy string `yaml:"seal_strategy" json:"seal_strategy" mapstructure:"seal_strategy"`

	// ShamirThreshold is the M in M-of-N Shamir splitting (0 = single key).
	ShamirThreshold int `yaml:"shamir_threshold" json:"shamir_threshold" mapstructure:"shamir_threshold"`

	// ShamirShares is the N in M-of-N Shamir splitting.
	ShamirShares int `yaml:"shamir_shares" json:"shamir_shares" mapstructure:"shamir_shares"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		SealStrategy: DefaultSealStrategy,
	}
}

// Validate checks configuration values for correctness.
func (c *Config) Validate() error {
	switch c.SealStrategy {
	case SealStrategySoftware, SealStrategyTPM2, SealStrategyPKCS11, "":
		// valid
	default:
		return &ConfigError{
			Field:   "SealStrategy",
			Message: "must be one of: software, tpm2, pkcs11",
		}
	}
	if c.ShamirThreshold < 0 {
		return &ConfigError{
			Field:   "ShamirThreshold",
			Message: "must be non-negative",
		}
	}
	if c.ShamirShares < 0 {
		return &ConfigError{
			Field:   "ShamirShares",
			Message: "must be non-negative",
		}
	}
	if c.ShamirThreshold > 0 && c.ShamirShares == 0 {
		return &ConfigError{
			Field:   "ShamirShares",
			Message: "must be set when ShamirThreshold is set",
		}
	}
	if c.ShamirShares > 0 && c.ShamirThreshold == 0 {
		return &ConfigError{
			Field:   "ShamirThreshold",
			Message: "must be set when ShamirShares is set",
		}
	}
	if c.ShamirThreshold > c.ShamirShares {
		return &ConfigError{
			Field:   "ShamirThreshold",
			Message: "must not exceed ShamirShares",
		}
	}
	return nil
}

// IsShamir returns true if the configuration specifies Shamir secret sharing.
func (c *Config) IsShamir() bool {
	return c.ShamirThreshold > 0 && c.ShamirShares > 0
}

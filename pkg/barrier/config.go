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

import (
	"slices"
	"strconv"
	"strings"
)

const (
	// SealStrategyNone disables encryption; the barrier is always open.
	SealStrategyNone = "none"

	// SealStrategyPassphrase is the canonical name for a passphrase/software-
	// derived encryption key (aligns with the seal layer's StrategyPassphrase
	// and qrdb's naming across the stack).
	SealStrategyPassphrase = "passphrase"

	// SealStrategySoftware is a backward-compatible alias for
	// SealStrategyPassphrase.
	SealStrategySoftware = "software"

	// SealStrategyShamir uses M-of-N Shamir secret sharing with a ceremony.
	SealStrategyShamir = "shamir"

	// SealStrategyTPM2 uses a TPM 2.0 to seal and unseal the barrier key.
	SealStrategyTPM2 = "tpm2"

	// SealStrategyPKCS11 uses a PKCS#11 hardware token to protect the barrier key.
	SealStrategyPKCS11 = "pkcs11"

	// DefaultSealStrategy is the default seal strategy when none is specified.
	DefaultSealStrategy = SealStrategySoftware

	// MinShamirThreshold is the smallest M accepted for an M-of-N Shamir
	// split. With M = 1 every share is the whole key: copies, not a split.
	MinShamirThreshold = 2
)

// sealStrategies lists every accepted seal strategy, in the order the
// validation message names them.
var sealStrategies = []string{
	SealStrategyNone,
	SealStrategyPassphrase,
	SealStrategySoftware,
	SealStrategyShamir,
	SealStrategyTPM2,
	SealStrategyPKCS11,
}

// ValidateShamirSplit returns ErrInvalidThreshold unless
// MinShamirThreshold <= threshold <= shares. It is the one Shamir rule the
// configuration, the Manager and platformctl apply.
func ValidateShamirSplit(threshold, shares int) error {
	if threshold < MinShamirThreshold || threshold > shares {
		return ErrInvalidThreshold
	}
	return nil
}

// Config holds barrier manager configuration.
type Config struct {
	// SealStrategy is the preferred sealing strategy (none, passphrase,
	// software, shamir, tpm2, pkcs11). Empty selects DefaultSealStrategy.
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
	if c.SealStrategy != "" && !slices.Contains(sealStrategies, c.SealStrategy) {
		return &ConfigError{
			Field:   "SealStrategy",
			Message: "must be one of: " + strings.Join(sealStrategies, ", "),
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
	if c.ShamirThreshold > 0 && ValidateShamirSplit(c.ShamirThreshold, c.ShamirShares) != nil {
		return &ConfigError{
			Field:   "ShamirThreshold",
			Message: "must be at least " + strconv.Itoa(MinShamirThreshold) + " and must not exceed ShamirShares",
		}
	}
	return nil
}

// IsShamir returns true if the configuration specifies Shamir secret sharing.
func (c *Config) IsShamir() bool {
	return c.ShamirThreshold > 0 && c.ShamirShares > 0
}

// RequiresCeremony returns true when the seal strategy requires an M-of-N
// officer enrollment ceremony before the barrier can be used: always for
// shamir, and for a passphrase strategy (passphrase, its alias software, or
// the empty default) that is split into Shamir shares.
func (c *Config) RequiresCeremony() bool {
	switch c.SealStrategy {
	case SealStrategyShamir:
		return true
	case SealStrategyPassphrase, SealStrategySoftware, "":
		return c.ShamirThreshold >= MinShamirThreshold
	default:
		return false
	}
}

// CeremonyConfig holds the parameters for initiating a barrier ceremony.
type CeremonyConfig struct {
	// SOPin is the Security Officer PIN used to authorize the ceremony.
	SOPin string

	// UserPin is the user-level PIN issued after ceremony completion.
	UserPin string

	// Threshold is the M in M-of-N: the minimum number of shares required
	// to reconstruct the barrier key.
	Threshold int

	// Officers is the list of security officers to enroll in the ceremony.
	Officers []OfficerConfig
}

// OfficerConfig describes a single security officer being enrolled in the
// M-of-N ceremony.
type OfficerConfig struct {
	// Username is the officer's unique identity.
	Username string

	// CSRPEM is the PEM-encoded certificate signing request submitted by
	// the officer.
	CSRPEM []byte
}

// CeremonyInitResult holds the result of a successful ceremony initialization.
type CeremonyInitResult struct {
	// SPKIPin is the SPKI fingerprint of the CA certificate.
	SPKIPin string

	// CACertPEM is the PEM-encoded CA certificate.
	CACertPEM string

	// TLSCertPEM is the PEM-encoded TLS certificate issued during ceremony.
	TLSCertPEM string

	// State is the ceremony state after initialization (e.g., "pending_claims").
	State string

	// ShareCount is the number of Shamir shares generated.
	ShareCount int
}

// CeremonyStatusInfo describes the current state of a ceremony.
type CeremonyStatusInfo struct {
	// State is the current ceremony state string (e.g., "pending_claims", "complete").
	State string

	// SPKIPin is the SPKI fingerprint once the CA has been provisioned.
	SPKIPin string
}

// CeremonyChallenge is the challenge nonce returned by BeginClaimCert that
// the officer must sign with their CSR private key.
type CeremonyChallenge struct {
	// NonceHex is the hex-encoded random nonce to be signed.
	NonceHex string

	// ExpiresAt is the RFC 3339 timestamp after which the nonce is invalid.
	ExpiresAt string
}

// CeremonyClaimCertResult holds the certificate issued to an officer after a
// successful challenge-response exchange.
type CeremonyClaimCertResult struct {
	// CertPEM is the PEM-encoded officer certificate.
	CertPEM string

	// CACertPEM is the PEM-encoded CA certificate that signed the officer cert.
	CACertPEM string
}

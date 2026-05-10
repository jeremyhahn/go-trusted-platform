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
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fido2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

var (
	ErrUnlockFailed         = errors.New("initrd: unlock failed")
	ErrNoStrategiesAvail    = errors.New("initrd: no unlock strategies available")
	ErrInvalidMode          = errors.New("initrd: invalid boot mode")
	ErrInvalidConfig        = errors.New("initrd: invalid configuration")
	ErrVolumeNotConfigured  = errors.New("initrd: volume not configured")
	ErrInstallationFailed   = errors.New("initrd: installation failed")
	ErrRecoveryFailed       = errors.New("initrd: recovery failed")
	ErrStrategyNotAvailable = errors.New("initrd: strategy not available")
)

// BootMode represents the operational mode
type BootMode int

const (
	// ModeInstall performs initial setup and key provisioning
	ModeInstall BootMode = iota

	// ModeBoot performs normal boot operations
	ModeBoot

	// ModeRecovery performs recovery boot with fallback options
	ModeRecovery

	// ModeMaintenance enters maintenance mode
	ModeMaintenance
)

func (m BootMode) String() string {
	switch m {
	case ModeInstall:
		return "install"
	case ModeBoot:
		return "boot"
	case ModeRecovery:
		return "recovery"
	case ModeMaintenance:
		return "maintenance"
	default:
		return "unknown"
	}
}

// Config represents initrd configuration
type Config struct {
	// Mode specifies the operational mode
	Mode BootMode

	// RootDevice is the encrypted root device path
	RootDevice string

	// BootDevice is the boot partition device path (EFI)
	BootDevice string

	// XKMSPath is the path to store sealed keys
	XKMSPath string

	// PCRBanks specifies which PCR banks to use (e.g., sha256, sha384)
	PCRBanks []string

	// PCRSelection specifies which PCRs to seal against
	PCRSelection []uint

	// UpgradePCRSelection specifies PCRs for upgrade unlock
	UpgradePCRSelection []uint

	// UnlockTimeout is the timeout per strategy in seconds
	UnlockTimeout int

	// FallbackMethods defines the ordered list of unlock methods to try
	FallbackMethods []luks.UnlockMethod

	// RetryCount is the number of retry attempts per strategy
	RetryCount int

	// EnableAuditLog enables audit logging of unlock attempts
	EnableAuditLog bool

	// AuditLogPath is the path to write audit logs
	AuditLogPath string

	// DisablePasswordPrompt prevents interactive password prompts in automated mode
	// When true, password strategy will fail immediately instead of blocking on stdin
	DisablePasswordPrompt bool

	// FIPS enables FIPS 140-3 compliant algorithms (PBKDF2 instead of Argon2id)
	FIPS bool

	// SecureWipePasses is the number of overwrite passes for installer.luks wipe
	// 1 = NIST SP 800-88 (SSD), 3 = DoD 5220.22-M, 7 = DoD ECE
	SecureWipePasses int
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.RootDevice == "" {
		return ErrInvalidConfig
	}
	if c.XKMSPath == "" {
		return ErrInvalidConfig
	}
	if len(c.PCRSelection) == 0 {
		return ErrInvalidConfig
	}
	if c.UnlockTimeout <= 0 {
		c.UnlockTimeout = 30 // default 30 seconds
	}
	if c.RetryCount <= 0 {
		c.RetryCount = 3 // default 3 retries
	}
	return nil
}

// UnlockStrategy defines an interface for volume unlock strategies
type UnlockStrategy interface {
	// Name returns the strategy name for logging
	Name() string

	// Priority returns execution priority (lower = higher priority)
	Priority() int

	// CanUnlock checks if this strategy can unlock the volume
	CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool

	// Unlock attempts to unlock the volume
	Unlock(ctx context.Context, volume *luks.VolumeConfig) error

	// Install performs installation-time setup for this strategy
	Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error
}

// Manager orchestrates the boot process
type Manager interface {
	// Initialize prepares the boot environment
	Initialize(ctx context.Context) error

	// DetectMode determines the current boot mode
	DetectMode(ctx context.Context) (BootMode, error)

	// Install performs initial setup and key provisioning
	Install(ctx context.Context, password []byte) error

	// Boot performs normal boot sequence
	Boot(ctx context.Context) error

	// Recovery performs recovery boot with user interaction
	Recovery(ctx context.Context) error

	// InteractiveRecovery provides an interactive recovery menu
	InteractiveRecovery(ctx context.Context) error

	// RegisterStrategy registers an unlock strategy
	RegisterStrategy(strategy UnlockStrategy)

	// UnlockVolumes attempts to unlock all configured volumes
	UnlockVolumes(ctx context.Context) error

	// Close cleans up resources
	Close() error
}

// Platform provides unified platform access
type Platform struct {
	// TPM provides TPM2 operations
	TPM xkmssdk.TrustedPlatformModule

	// LUKS provides LUKS operations
	LUKS luks.Handler

	// FIDO2 provides FIDO2 authentication
	FIDO2 fido2.Handler

	// XKMS provides key management (optional, can be nil for minimal boot)
	XKMS *platform.XKMS

	// Backend provides direct key storage access for minimal boot scenarios
	// When XKMS is nil, this is used directly for TPM unsealing
	Backend xkmssdk.TPMKeyBackend

	// Config is the initrd configuration
	Config *Config
}

// UnlockAttempt records an unlock attempt for audit logging
type UnlockAttempt struct {
	// Strategy that was attempted
	Strategy string

	// Success indicates if the attempt succeeded
	Success bool

	// Error message if failed
	Error string

	// Duration in milliseconds
	Duration int64

	// Timestamp of the attempt
	Timestamp int64
}

// AuditLog tracks unlock attempts
type AuditLog struct {
	// BootTimestamp when boot started
	BootTimestamp int64

	// Mode that was detected
	Mode BootMode

	// Attempts lists all unlock attempts
	Attempts []UnlockAttempt

	// FinalStatus indicates overall success
	FinalStatus bool

	// TotalDuration in milliseconds
	TotalDuration int64
}

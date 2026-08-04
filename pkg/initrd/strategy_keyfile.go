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
	"fmt"
	"os"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// KeyfileStrategy implements unlock using a keyfile stored during installation.
// This is primarily used for firstboot before TPM provisioning is complete.
// The keyfile should be securely deleted after successful TPM enrollment.
type KeyfileStrategy struct {
	platform     *Platform
	logger       *logging.Logger
	keyfilePaths []string
}

// NewKeyfileStrategy creates a new keyfile-based unlock strategy
func NewKeyfileStrategy(platform *Platform, logger *logging.Logger) *KeyfileStrategy {
	// Keyfile location: inside the encrypted installer container mounted during firstboot
	// The installer.luks container is mounted to /mnt/installer by the boot command
	// SECURITY: The LUKS key is NEVER stored in plaintext on the EFI partition
	keyfilePaths := []string{
		"/mnt/installer/luks-key.bin",
	}
	return &KeyfileStrategy{
		platform:     platform,
		logger:       logger,
		keyfilePaths: keyfilePaths,
	}
}

// Name returns the strategy name
func (s *KeyfileStrategy) Name() string {
	return "Keyfile"
}

// Priority returns the unlock priority (higher = tried first)
// Keyfile has high priority (80) because it's specifically for firstboot automation
func (s *KeyfileStrategy) Priority() int {
	return 80
}

// CanUnlock checks if a keyfile exists and is readable at any of the known locations
func (s *KeyfileStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	s.logger.Debugf("[KEYFILE] Checking if keyfile unlock is available")

	for _, path := range s.keyfilePaths {
		s.logger.Debugf("[KEYFILE] Checking keyfile path: %s", path)

		// Check if keyfile exists
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				s.logger.Debugf("[KEYFILE] Keyfile does not exist: %s", path)
			} else {
				s.logger.Warnf("[KEYFILE] Error checking keyfile %s: %v", path, err)
			}
			continue
		}

		// Check if it's a regular file
		if !info.Mode().IsRegular() {
			s.logger.Warnf("[KEYFILE] Keyfile is not a regular file: %s", path)
			continue
		}

		// Check file permissions - should be readable
		if info.Mode().Perm()&0400 == 0 {
			s.logger.Warnf("[KEYFILE] Keyfile is not readable: %s (mode: %v)", path, info.Mode())
			continue
		}

		s.logger.Infof("[KEYFILE] Keyfile is available for unlock: %s", path)
		return true
	}

	s.logger.Debugf("[KEYFILE] No keyfile found at any of: %v", s.keyfilePaths)
	return false
}

// Unlock attempts to unlock the LUKS device using the first available keyfile
func (s *KeyfileStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("[KEYFILE] Attempting keyfile unlock for %s", volume.DevicePath)

	// Find first available keyfile
	var keyfilePath string
	for _, path := range s.keyfilePaths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			keyfilePath = path
			break
		}
	}

	if keyfilePath == "" {
		return &MessageError{Msg: fmt.Sprintf("[KEYFILE] no keyfile found at any of: %v", s.keyfilePaths)}
	}

	s.logger.Infof("[KEYFILE] Using keyfile: %s", keyfilePath)

	// Read keyfile contents
	keydata, err := os.ReadFile(keyfilePath)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("[KEYFILE] failed to read keyfile %s", keyfilePath), Err: err}
	}

	// For binary key files (like luks-key.bin), don't trim
	// For text files, we might want to trim whitespace
	password := keydata
	if strings.HasSuffix(keyfilePath, ".key") {
		// Text key file - trim whitespace
		password = []byte(strings.TrimSpace(string(keydata)))
	}

	if len(password) == 0 {
		return &MessageError{Msg: fmt.Sprintf("[KEYFILE] keyfile is empty: %s", keyfilePath)}
	}

	s.logger.Infof("[KEYFILE] Keyfile read successfully (%d bytes), attempting unlock...", len(password))

	// Attempt LUKS unlock
	openOpts := &luks.OpenOptions{
		AllowDiscards: volume.AllowDiscards,
		Timeout:       volume.Timeout,
	}

	err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, password, openOpts)
	if err != nil {
		return &WrappedError{Msg: "[KEYFILE] failed to unlock with keyfile", Err: err}
	}

	s.logger.Infof("[KEYFILE] Successfully unlocked %s with keyfile from %s", volume.DevicePath, keyfilePath)
	s.logger.Info("[KEYFILE] Keyfile will be deleted by firstboot service after TPM provisioning")

	return nil
}

// Install performs installation-time setup for the keyfile strategy
// The keyfile is already saved by the installer, so this is a no-op
func (s *KeyfileStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("[KEYFILE] Installing keyfile strategy for %s", volume.DevicePath)
	s.logger.Info("[KEYFILE] Keyfile is written by installer, no additional setup needed")
	return nil
}

// GetKeyfilePath returns the path to the first available keyfile, or empty if none found
func (s *KeyfileStrategy) GetKeyfilePath() string {
	for _, path := range s.keyfilePaths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

// GetKeyfilePaths returns all configured keyfile paths
func (s *KeyfileStrategy) GetKeyfilePaths() []string {
	return s.keyfilePaths
}

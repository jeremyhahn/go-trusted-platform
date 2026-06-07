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
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// FIDO2Strategy unlocks using FIDO2 hardware security key
type FIDO2Strategy struct {
	platform *Platform
	logger   *logging.Logger
	priority int
}

// NewFIDO2Strategy creates a new FIDO2 unlock strategy
func NewFIDO2Strategy(platform *Platform, logger *logging.Logger) *FIDO2Strategy {
	return &FIDO2Strategy{
		platform: platform,
		logger:   logger,
		priority: 3, // Third priority - requires user presence
	}
}

// Name returns the strategy name
func (s *FIDO2Strategy) Name() string {
	return "FIDO2"
}

// Priority returns the execution priority
func (s *FIDO2Strategy) Priority() int {
	return s.priority
}

// CanUnlock checks if this strategy can unlock the volume
func (s *FIDO2Strategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	// Check if FIDO2 handler is available
	if s.platform.FIDO2 == nil {
		s.logger.Debug("FIDO2: Handler not available")
		return false
	}

	// Check if volume has a FIDO2 key slot configured
	for _, slot := range volume.KeySlots {
		if slot.Type == luks.UnlockFIDO2 {
			return true
		}
	}

	s.logger.Debug("FIDO2: No FIDO2 key slot configured")
	return false
}

// Unlock attempts to unlock the volume using FIDO2
func (s *FIDO2Strategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("Attempting FIDO2 unlock for %s", volume.DevicePath)

	// Find FIDO2 key slots
	for _, slot := range volume.KeySlots {
		if slot.Type != luks.UnlockFIDO2 {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		s.logger.Debugf("Trying FIDO2 slot %d", slot.Index)
		s.logger.Info("Please touch your security key...")

		// Load authentication config from slot metadata
		authConfig, err := s.loadAuthConfig(slot)
		if err != nil {
			s.logger.Warnf("Failed to load auth config for slot %d: %v", slot.Index, err)
			continue
		}

		// Authenticate with FIDO2 device
		key, err := s.platform.FIDO2.UnlockWithKey(authConfig)
		if err != nil {
			s.logger.Warnf("FIDO2 authentication failed for slot %d: %v", slot.Index, err)
			continue
		}

		// Attempt LUKS unlock
		openOpts := &luks.OpenOptions{
			AllowDiscards: volume.AllowDiscards,
			Timeout:       volume.Timeout,
			KeySlot:       &slot.Index,
		}

		err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, key, openOpts)
		if err == nil {
			s.logger.Infof("Successfully unlocked %s with FIDO2 slot %d",
				volume.DevicePath, slot.Index)
			return nil
		}

		s.logger.Warnf("LUKS open failed with slot %d: %v", slot.Index, err)
	}

	return fmt.Errorf("all FIDO2 slots failed")
}

// Install performs installation-time setup for FIDO2 strategy
func (s *FIDO2Strategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("Installing FIDO2 strategy for %s", volume.DevicePath)

	// Check if FIDO2 handler is available
	if s.platform.FIDO2 == nil {
		return fmt.Errorf("FIDO2 handler not available")
	}

	// Find the first available FIDO2 slot
	var targetSlot *luks.KeySlot
	for i := range volume.KeySlots {
		if volume.KeySlots[i].Type == luks.UnlockFIDO2 {
			targetSlot = &volume.KeySlots[i]
			break
		}
	}

	if targetSlot == nil {
		return fmt.Errorf("no FIDO2 key slot configured")
	}

	// Create enrollment config
	enrollConfig := &fido2.EnrollmentConfig{
		RelyingParty: fido2.RelyingParty{
			ID:   "luks-root",
			Name: fmt.Sprintf("LUKS %s", volume.MappingName),
		},
		User: fido2.User{
			ID:          []byte(volume.MappingName),
			Name:        "root",
			DisplayName: "Root Volume",
		},
		Timeout: time.Duration(s.platform.Config.UnlockTimeout) * time.Second,
	}

	s.logger.Info("Please touch your security key to enroll...")

	// Enroll FIDO2 credential
	result, err := s.platform.FIDO2.EnrollKey(enrollConfig)
	if err != nil {
		return fmt.Errorf("failed to enroll FIDO2 key: %w", err)
	}

	// The FIDO2 handler should return a key derived from the HMAC secret
	// For now, we'll use the credential ID as the key material
	// In production, this would be the HMAC-secret derived key
	key := result.CredentialID[:32] // Use first 32 bytes

	// Add the key to the LUKS key slot
	// Use FIPS-appropriate PBKDF (auto-detected from kernel)
	addOpts := &luks.AddKeyOptions{
		KeySlot: &targetSlot.Index,
		KDFType: fips.GetKDF(),
		Hash:    fips.GetHash(),
	}

	s.logger.Info("Adding FIDO2 key to LUKS", "slot", targetSlot.Index, "fips", fips.IsEnabled(), "kdf", addOpts.KDFType)
	err = s.platform.LUKS.AddKey(ctx, volume.DevicePath, password, key, addOpts)
	if err != nil {
		return fmt.Errorf("failed to add key to LUKS slot %d: %w", targetSlot.Index, err)
	}

	// Store enrollment metadata in slot
	s.storeEnrollmentMetadata(targetSlot, result)

	s.logger.Infof("Successfully installed FIDO2 strategy in slot %d", targetSlot.Index)
	return nil
}

// loadAuthConfig loads authentication configuration from key slot
func (s *FIDO2Strategy) loadAuthConfig(slot luks.KeySlot) (*fido2.AuthenticationConfig, error) {
	// In a real implementation, this would load stored credential data
	// from the LUKS2 token metadata or external storage
	//
	// For now, return a basic config - this would need to be enhanced
	// to store and retrieve the actual credential ID and other metadata
	config := &fido2.AuthenticationConfig{
		RelyingPartyID: "luks-root",
		Timeout:        30 * time.Second,
		CredentialID:   nil, // Would be loaded from metadata
		Salt:           nil, // Would be loaded from metadata
	}

	return config, nil
}

// storeEnrollmentMetadata stores FIDO2 enrollment metadata
func (s *FIDO2Strategy) storeEnrollmentMetadata(slot *luks.KeySlot, result *fido2.EnrollmentResult) {
	// In a real implementation, this would store the credential ID,
	// salt, and other metadata in the LUKS2 token area or external storage
	//
	// This ensures we can retrieve the necessary data during boot to
	// perform authentication
	s.logger.Debugf("Storing FIDO2 enrollment metadata for slot %d", slot.Index)
	// DEFERRED: Implement metadata storage via LUKS2 tokens. Blocked by: go-luks2 token API.
}

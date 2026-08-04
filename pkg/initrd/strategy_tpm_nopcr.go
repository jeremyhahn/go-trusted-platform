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
	"crypto/rand"
	"os"
	"path/filepath"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// TPMNoPCRStrategy unlocks using TPM WITHOUT PCR policy
// This is used during installation to create an initial sealed key
// that allows the first boot to succeed before re-sealing with PCR policy
type TPMNoPCRStrategy struct {
	platform *Platform
	logger   *logging.Logger
	priority int
}

// NewTPMNoPCRStrategy creates a new TPM no-PCR unlock strategy
func NewTPMNoPCRStrategy(platform *Platform, logger *logging.Logger) *TPMNoPCRStrategy {
	return &TPMNoPCRStrategy{
		platform: platform,
		logger:   logger,
		priority: 5, // Lower priority than PCR strategies, only for install/recovery
	}
}

// Name returns the strategy name
func (s *TPMNoPCRStrategy) Name() string {
	return "TPM-NoPCR"
}

// Priority returns the execution priority
func (s *TPMNoPCRStrategy) Priority() int {
	return s.priority
}

// CanUnlock checks if this strategy can unlock the volume
func (s *TPMNoPCRStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	// Check if TPM is available
	if s.platform.TPM == nil {
		s.logger.Debug("TPM-NoPCR: TPM not available")
		return false
	}

	// Check if sealed key files exist
	sealPubPath := filepath.Join(s.platform.Config.XKMSPath, "seal.pub")
	sealPrivPath := filepath.Join(s.platform.Config.XKMSPath, "seal.priv")

	if _, err := os.Stat(sealPubPath); err != nil {
		s.logger.Debug("TPM-NoPCR: seal.pub not found")
		return false
	}

	if _, err := os.Stat(sealPrivPath); err != nil {
		s.logger.Debug("TPM-NoPCR: seal.priv not found")
		return false
	}

	s.logger.Debug("TPM-NoPCR: sealed key files found")
	return true
}

// Unlock attempts to unlock the volume using TPM without PCR policy
func (s *TPMNoPCRStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("Attempting TPM-NoPCR unlock for %s", volume.DevicePath)

	// Create key attributes for unsealing
	// Get Platform KeyStore SRK handle from config (default 0x81000002)
	// ALL LUKS keys are sealed under the Platform KeyStore SRK
	platformSRKHandle := s.getPlatformKeystoreSRKHandle()
	platformPolicy := s.getPlatformPolicy()

	// Get Platform KeyStore SRK attributes as parent
	srkAttrs, err := s.platform.TPM.KeyAttributes(xkmssdk.TPMHandle(platformSRKHandle))
	if err != nil {
		return &WrappedError{Msg: "failed to get Platform KeyStore SRK attributes", Err: err}
	}

	// Set PlatformPolicy on parent SRK so CreateSession uses correct auth
	srkAttrs.PlatformPolicy = platformPolicy

	// Create key attributes for unsealing
	// The sealed OBJECT has NO PCR policy, but parent SRK may have platform policy
	attrs := &xkmssdk.KeyAttributes{
		CN:             "luks-root-nopcr",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: false, // NO PCR policy on sealed OBJECT
		Parent:         srkAttrs,
	}

	// Load sealed data from files
	sealPubPath := filepath.Join(s.platform.Config.XKMSPath, "seal.pub")
	sealPrivPath := filepath.Join(s.platform.Config.XKMSPath, "seal.priv")

	pubBlob, err := os.ReadFile(sealPubPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read seal.pub", Err: err}
	}
	privBlob, err := os.ReadFile(sealPrivPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read seal.priv", Err: err}
	}

	sealedData := &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2,
		TPMPublic:  pubBlob,
		TPMPrivate: privBlob,
	}

	// Get the backend for retrieving sealed data
	var backend interface{}
	if s.platform.XKMS != nil {
		backend = s.platform.XKMS.Backend()
	} else if s.platform.Backend != nil {
		backend = s.platform.Backend
	}

	// Unseal the key
	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: attrs,
		Backend:       backend,
	}
	key, err := s.platform.TPM.Unseal(ctx, sealedData, unsealOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to unseal key", Err: err}
	}

	// Attempt LUKS unlock (any available slot with sealed key)
	openOpts := &luks.OpenOptions{
		AllowDiscards: volume.AllowDiscards,
		Timeout:       volume.Timeout,
		KeySlot:       nil, // Try all slots
	}

	err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, key, openOpts)
	if err == nil {
		s.logger.Infof("Successfully unlocked %s with TPM-NoPCR", volume.DevicePath)
		return nil
	}

	return &WrappedError{Msg: "LUKS open failed", Err: err}
}

// Install performs installation-time setup for TPM-NoPCR strategy
// This creates a TPM-sealed key WITHOUT PCR policy for initial boot
func (s *TPMNoPCRStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("Installing TPM-NoPCR strategy for %s", volume.DevicePath)

	// Generate a new random LUKS key (32 bytes = 256 bits)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return &WrappedError{Msg: "failed to generate random key", Err: err}
	}

	// Get Platform KeyStore SRK handle from config (default 0x81000002)
	// ALL LUKS keys are sealed under the Platform KeyStore SRK
	platformSRKHandle := s.getPlatformKeystoreSRKHandle()
	platformPolicy := s.getPlatformPolicy()

	// Get Platform KeyStore SRK attributes as parent
	srkAttrs, err := s.platform.TPM.KeyAttributes(xkmssdk.TPMHandle(platformSRKHandle))
	if err != nil {
		return &WrappedError{Msg: "failed to get Platform KeyStore SRK attributes", Err: err}
	}

	// Set PlatformPolicy on parent SRK so CreateSession uses correct auth
	srkAttrs.PlatformPolicy = platformPolicy

	// Create key attributes for TPM sealing WITHOUT PCR policy on the sealed OBJECT
	attrs := &xkmssdk.KeyAttributes{
		CN:             "luks-root-nopcr",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: false, // NO PCR policy on sealed OBJECT - allows first boot to succeed
		Parent:         srkAttrs,
	}

	// Get the backend for storing sealed data
	var backend interface{}
	if s.platform.XKMS != nil {
		backend = s.platform.XKMS.Backend()
	} else if s.platform.Backend != nil {
		backend = s.platform.Backend
	}

	// Seal the key without PCR policy
	s.logger.Info("Sealing key to TPM (without PCR policy for first boot)")
	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: attrs,
		Backend:       backend,
	}
	sealedData, err := s.platform.TPM.Seal(ctx, key, sealOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to seal key", Err: err}
	}

	// Save sealed data to files
	sealPubPath := filepath.Join(s.platform.Config.XKMSPath, "seal.pub")
	sealPrivPath := filepath.Join(s.platform.Config.XKMSPath, "seal.priv")

	if err := os.MkdirAll(s.platform.Config.XKMSPath, 0700); err != nil {
		return &WrappedError{Msg: "failed to create xkms directory", Err: err}
	}
	if err := os.WriteFile(sealPubPath, sealedData.TPMPublic, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal.pub", Err: err}
	}
	if err := os.WriteFile(sealPrivPath, sealedData.TPMPrivate, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal.priv", Err: err}
	}

	// Add the key to next available LUKS keyslot (let go-luks2 auto-assign)
	// Use FIPS-appropriate PBKDF (auto-detected from kernel)
	addOpts := &luks.AddKeyOptions{
		KeySlot: nil, // Auto-assign to next available slot
		KDFType: fips.GetKDF(),
		Hash:    fips.GetHash(),
	}

	s.logger.Info("Adding TPM-sealed key to LUKS (auto-selecting available slot)",
		"fips", fips.IsEnabled(), "kdf", addOpts.KDFType)
	err = s.platform.LUKS.AddKey(ctx, volume.DevicePath, password, key, addOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to add key to LUKS", Err: err}
	}

	s.logger.Info("Successfully installed TPM-NoPCR strategy")
	s.logger.Info("Note: PCR-sealed keys should be created on first boot for enhanced security")
	return nil
}

// getPlatformKeystoreSRKHandle returns the Platform KeyStore SRK handle from TPM config.
// This is the dedicated SRK (default 0x81000002) used for ALL platform key operations.
func (s *TPMNoPCRStrategy) getPlatformKeystoreSRKHandle() uint32 {
	if s.platform.TPM != nil {
		config := s.platform.TPM.Config()
		if config != nil && config.PlatformSRK != nil && config.PlatformSRK.SRKHandle != 0 {
			return config.PlatformSRK.SRKHandle
		}
	}
	// Default Platform KeyStore SRK handle
	return 0x81000002
}

// getPlatformPolicy returns the platform-policy setting from TPM config.
// When true, the Platform KeyStore SRK has PCR auth policy.
func (s *TPMNoPCRStrategy) getPlatformPolicy() bool {
	if s.platform.TPM != nil {
		config := s.platform.TPM.Config()
		if config != nil && config.PlatformSRK != nil {
			return config.PlatformSRK.PlatformPolicy
		}
	}
	return true // Default to platform policy enabled
}

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

package luks

import (
	"context"
	"fmt"

	goluks "github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// CryptsetupHandler implements the Handler and TokenHandler interfaces using go-luks2
type CryptsetupHandler struct {
	config *Config
	logger interface{}
}

// Ensure CryptsetupHandler implements both Handler and HandlerWithTokens
var (
	_ Handler           = (*CryptsetupHandler)(nil)
	_ HandlerWithTokens = (*CryptsetupHandler)(nil)
)

// NewCryptsetupHandlerImpl creates a new LUKS handler using go-luks2.
// The returned handler implements both Handler and HandlerWithTokens interfaces.
func NewCryptsetupHandlerImpl(config *Config, logger interface{}) (*CryptsetupHandler, error) {
	if config == nil {
		config = &Config{}
	}
	return &CryptsetupHandler{
		config: config,
		logger: logger,
	}, nil
}

// IsLUKS checks if a device is a LUKS volume
func (h *CryptsetupHandler) IsLUKS(ctx context.Context, devicePath string) (bool, error) {
	_, _, err := goluks.ReadHeader(devicePath)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Format formats a device with LUKS encryption
func (h *CryptsetupHandler) Format(ctx context.Context, devicePath string, password []byte, opts *FormatOptions) error {
	formatOpts := goluks.FormatOptions{
		Device:     devicePath,
		Passphrase: password,
	}

	if opts != nil {
		if opts.Label != "" {
			formatOpts.Label = opts.Label
		}
		if opts.Subsystem != "" {
			formatOpts.Subsystem = opts.Subsystem
		}
		if opts.Cipher != "" {
			formatOpts.Cipher = opts.Cipher
		}
		if opts.CipherMode != "" {
			formatOpts.CipherMode = opts.CipherMode
		}
		if opts.KeySize > 0 {
			formatOpts.KeySize = opts.KeySize
		}
		if opts.HashAlgo != "" {
			formatOpts.HashAlgo = opts.HashAlgo
		} else if opts.HashAlgorithm != "" {
			formatOpts.HashAlgo = opts.HashAlgorithm
		}
		if opts.SectorSize > 0 {
			formatOpts.SectorSize = opts.SectorSize
		}
		if opts.KDFType != "" {
			formatOpts.KDFType = opts.KDFType
		} else if opts.PBKDFType != "" {
			formatOpts.KDFType = opts.PBKDFType
		}
		if opts.PBKDFIterTime > 0 {
			formatOpts.PBKDFIterTime = opts.PBKDFIterTime
		}
		if opts.Argon2Time > 0 {
			formatOpts.Argon2Time = opts.Argon2Time
		}
		if opts.Argon2Memory > 0 {
			formatOpts.Argon2Memory = opts.Argon2Memory
		}
		if opts.Argon2Parallel > 0 {
			formatOpts.Argon2Parallel = opts.Argon2Parallel
		}
	}

	return goluks.Format(formatOpts)
}

// AddKey adds a new key to a LUKS volume
func (h *CryptsetupHandler) AddKey(ctx context.Context, devicePath string, existingPassword, newPassword []byte, opts *AddKeyOptions) error {
	var addOpts *goluks.AddKeyOptions
	if opts != nil {
		addOpts = &goluks.AddKeyOptions{}
		if opts.KeySlot != nil {
			addOpts.Keyslot = opts.KeySlot
		} else if opts.Keyslot != nil {
			addOpts.Keyslot = opts.Keyslot
		}
		// Pass KDF type and hash algorithm to go-luks2
		if opts.KDFType != "" {
			addOpts.KDFType = opts.KDFType
		}
		if opts.Hash != "" {
			addOpts.Hash = opts.Hash
		}
	}
	return goluks.AddKey(devicePath, existingPassword, newPassword, addOpts)
}

// Open opens (unlocks) a LUKS volume
func (h *CryptsetupHandler) Open(ctx context.Context, devicePath, mappingName string, password []byte, opts *OpenOptions) error {
	return goluks.Unlock(devicePath, password, mappingName)
}

// IsOpen checks if a LUKS volume is already unlocked (device-mapper mapping exists)
func (h *CryptsetupHandler) IsOpen(ctx context.Context, mappingName string) bool {
	return goluks.IsUnlocked(mappingName)
}

// Close closes (locks) a LUKS volume
func (h *CryptsetupHandler) Close(ctx context.Context, mappingName string) error {
	return goluks.Lock(mappingName)
}

// Status returns status information about a LUKS volume
func (h *CryptsetupHandler) Status(ctx context.Context, devicePath string) (*VolumeStatus, error) {
	info, err := goluks.GetVolumeInfo(devicePath)
	if err != nil {
		return nil, err
	}

	status := &VolumeStatus{
		DevicePath: devicePath,
		Cipher:     info.Cipher,
		KeySize:    info.KeySize,
		UUID:       info.UUID,
	}

	// Get keyslot info
	keyslots, err := goluks.ListKeyslots(devicePath)
	if err == nil {
		for _, ks := range keyslots {
			status.ActiveSlots = append(status.ActiveSlots, ks.ID)
		}
	}

	// Determine version
	_, metadata, err := goluks.ReadHeader(devicePath)
	if err == nil && metadata != nil {
		status.Version = LUKSVersion2
	}

	return status, nil
}

// Version returns the LUKS version of a device
func (h *CryptsetupHandler) Version(ctx context.Context, devicePath string) (LUKSVersion, error) {
	_, _, err := goluks.ReadHeader(devicePath)
	if err != nil {
		return 0, err
	}
	return LUKSVersion2, nil
}

// RemoveKey removes a key from a specific slot
func (h *CryptsetupHandler) RemoveKey(ctx context.Context, devicePath string, slot int) error {
	return goluks.KillKeyslot(devicePath, slot)
}

// KillSlot kills (disables) a key slot
func (h *CryptsetupHandler) KillSlot(ctx context.Context, devicePath string, slot int) error {
	return goluks.KillKeyslot(devicePath, slot)
}

// ChangeKey changes the key in a specific slot
func (h *CryptsetupHandler) ChangeKey(ctx context.Context, devicePath string, slot int, oldPassword, newPassword []byte) error {
	return goluks.ChangeKey(devicePath, oldPassword, newPassword, slot)
}

// UUID returns the UUID of a LUKS volume
func (h *CryptsetupHandler) UUID(ctx context.Context, devicePath string) (string, error) {
	info, err := goluks.GetVolumeInfo(devicePath)
	if err != nil {
		return "", err
	}
	return info.UUID, nil
}

// DumpHeader dumps the LUKS header information
func (h *CryptsetupHandler) DumpHeader(ctx context.Context, devicePath string) (map[string]interface{}, error) {
	header, metadata, err := goluks.ReadHeader(devicePath)
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	if header != nil {
		result["magic"] = string(header.Magic[:])
		result["version"] = header.Version
		result["header_size"] = header.HeaderSize
		result["sequence_id"] = header.SequenceID
		result["label"] = string(header.Label[:])
		result["checksum_algorithm"] = string(header.ChecksumAlgorithm[:])
		result["salt"] = header.Salt
		result["uuid"] = string(header.UUID[:])
		result["subsystem"] = string(header.SubsystemLabel[:])
		result["header_offset"] = header.HeaderOffset
	}

	if metadata != nil {
		result["keyslots"] = metadata.Keyslots
		result["tokens"] = metadata.Tokens
		result["segments"] = metadata.Segments
		result["digests"] = metadata.Digests
		result["config"] = metadata.Config
	}

	return result, nil
}

// TestKey tests if a password is valid for a LUKS volume
func (h *CryptsetupHandler) TestKey(ctx context.Context, devicePath string, password []byte, slot *int) error {
	tempName := "luks-test-verify"
	err := goluks.Unlock(devicePath, password, tempName)
	if err != nil {
		return err
	}
	return goluks.Lock(tempName)
}

// Resize resizes an open LUKS volume
func (h *CryptsetupHandler) Resize(ctx context.Context, mappingName string, newSize *uint64) error {
	return fmt.Errorf("resize not yet implemented in go-luks2")
}

// Suspend suspends an open LUKS volume (dm-crypt suspend)
func (h *CryptsetupHandler) Suspend(ctx context.Context, mappingName string) error {
	return fmt.Errorf("suspend not yet implemented in go-luks2")
}

// Resume resumes a suspended LUKS volume
func (h *CryptsetupHandler) Resume(ctx context.Context, mappingName string, password []byte) error {
	return fmt.Errorf("resume not yet implemented in go-luks2")
}
